// 文件名：src/utils/webdavUtils.ts
import { R2Object, R2ListOptions } from '@cloudflare/workers-types';
import { WebDAVProps } from '../types';

/**
 * 规范化路径，移除 .. 和 .，防止路径遍历攻击
 * @param rawPath - 原始路径（已解码或未解码）
 * @returns 安全的标准路径
 */
function normalizePath(rawPath: string): string {
  // 1. 解码（防止 %2e%2e/ 等双重编码攻击）
  let decoded: string;
  try {
    decoded = decodeURIComponent(rawPath);
  } catch {
    decoded = rawPath;
  }
  // 2. 统一分隔符
  decoded = decoded.replace(/\\/g, '/');
  // 3. 分割并解析
  const parts = decoded.split('/');
  const resolved: string[] = [];
  for (const part of parts) {
    if (part === '' || part === '.') continue;
    if (part === '..') {
      resolved.pop();
    } else {
      resolved.push(part);
    }
  }
  // 4. 组装结果
  let result = resolved.join('/');
  // 5. 保留尾斜杠（如果原路径以 '/' 结尾）
  if (rawPath.endsWith('/') || decoded.endsWith('/')) {
    result += '/';
  }
  return result;
}

/**
 * 提取请求对应的资源路径（相对于存储桶根目录）
 * @param request - 原始请求
 * @returns 安全规范化的路径
 */
export function make_resource_path(request: Request): string {
  const url = new URL(request.url);
  const rawPath = url.pathname.slice(1); // 去掉开头的 '/'
  return normalizePath(rawPath);
}

/**
 * 遍历给定前缀下的所有对象和子目录（使用 delimiter: '/'）
 * @param bucket - R2 存储桶
 * @param prefix - 要列出的前缀
 * @returns 异步生成器，产生 R2Object（文件）和目录占位符（customMetadata.resourcetype = 'collection'）
 */
export async function* listAll(bucket: R2Bucket, prefix: string): AsyncGenerator<R2Object> {
  const options: R2ListOptions = { prefix, delimiter: '/' };
  let result = await bucket.list(options);
  let hasMore = result.truncated;

  while (true) {
    // 1. 返回普通文件对象
    for (const obj of result.objects) {
      yield obj;
    }

    // 2. 返回子目录（commonPrefixes）
    for (const dirPrefix of result.delimitedPrefixes) {
      // 构造一个伪目录对象，用于统一处理
      const fakeDir: R2Object = {
        key: dirPrefix,                     // 以 '/' 结尾
        size: 0,
        etag: '',
        uploaded: new Date(),
        httpMetadata: null,
        customMetadata: { resourcetype: 'collection' },
        // 以下为满足类型定义的占位（R2Object 实际还需要其他字段，但运行时不会使用）
        version: '',
        checksums: { md5: '' }
      } as R2Object;
      yield fakeDir;
    }

    if (!hasMore) break;
    if (result.cursor) {
      result = await bucket.list({ ...options, cursor: result.cursor });
      hasMore = result.truncated;
    } else {
      break;
    }
  }
}

/**
 * 转义 XML 特殊字符，防止 XML 注入和格式错误
 * @param unsafe - 未转义的字符串
 * @returns 转义后的字符串
 */
function escapeXml(unsafe: string): string {
  if (!unsafe) return '';
  return unsafe.replace(/[<>&'"]/g, (c) => {
    switch (c) {
      case '<': return '&lt;';
      case '>': return '&gt;';
      case '&': return '&amp;';
      case '\'': return '&apos;';
      case '"': return '&quot;';
      default: return c;
    }
  });
}

/**
 * 将 R2Object 转换为 WebDAV 属性对象
 * @param object - R2 对象或 null
 * @returns 标准化属性
 */
export function fromR2Object(object: R2Object | null): WebDAVProps {
  if (!object) {
    // 理论上不会发生，但保留逻辑用于安全
    return {
      creationdate: new Date().toUTCString(),
      displayname: undefined,
      getcontentlanguage: undefined,
      getcontentlength: '0',
      getcontenttype: undefined,
      getetag: undefined,
      getlastmodified: new Date().toUTCString(),
      resourcetype: 'collection'
    };
  }

  // 提取显示名称：取路径最后一段（对于目录要去掉尾斜杠）
  let displayname = object.key.split('/').filter(p => p.length > 0).pop() || '';
  if (object.customMetadata?.resourcetype === 'collection' && displayname === '') {
    // 目录键如 'folder/' 导致 pop 为空，手动提取
    displayname = object.key.slice(0, -1).split('/').pop() || '';
  }

  return {
    creationdate: object.uploaded.toUTCString(),
    displayname,
    getcontentlanguage: object.httpMetadata?.contentLanguage,
    getcontentlength: object.size.toString(),
    getcontenttype: object.httpMetadata?.contentType,
    getetag: object.etag,
    getlastmodified: object.uploaded.toUTCString(),
    resourcetype: object.customMetadata?.resourcetype || ''
  };
}

/**
 * 生成单个资源的 PROPFIND 响应片段
 * @param baseUrl - 当前请求的完整 URL（用于构建正确的 href）
 * @param resourcePath - 资源的完整路径（相对于存储桶根，不包含 bucket 名）
 * @param prop - WebDAV 属性
 * @returns XML 片段字符串
 */
function generatePropResponse(baseUrl: string, resourcePath: string, prop: WebDAVProps): string {
  // 构建正确的 href：基于请求的 baseUrl，去掉尾部的 /（如果有），再附上资源路径
  let base = baseUrl.endsWith('/') ? baseUrl.slice(0, -1) : baseUrl;
  // 确保资源路径以 / 开头
  let href = resourcePath ? (resourcePath.startsWith('/') ? resourcePath : '/' + resourcePath) : '/';
  // 处理目录加尾部斜杠
  if (prop.resourcetype === 'collection' && !href.endsWith('/')) {
    href += '/';
  }
  // URL 编码特殊字符（但保留 /）
  href = href.split('/').map(seg => encodeURIComponent(seg)).join('/');

  // 组装完整的绝对 URL（如果 baseUrl 是相对的，也可以直接用相对路径，但 WebDAV 客户端通常支持相对路径）
  // 这里直接使用相对路径（以 / 开头），更可靠
  const finalHref = href;

  // 转义需要输出的动态值
  const escapedCreationdate = escapeXml(prop.creationdate);
  const escapedContentlength = escapeXml(prop.getcontentlength);
  const escapedContenttype = escapeXml(prop.getcontenttype || '');
  const escapedEtag = escapeXml(prop.getetag || '');
  const escapedLastmodified = escapeXml(prop.getlastmodified);
  const collectionTag = prop.resourcetype === 'collection' ? '<D:collection/>' : '';

  return `  <D:response>
    <D:href>${finalHref}</D:href>
    <D:propstat>
      <D:prop>
        <D:creationdate>${escapedCreationdate}</D:creationdate>
        <D:getcontentlength>${escapedContentlength}</D:getcontentlength>
        <D:getcontenttype>${escapedContenttype}</D:getcontenttype>
        <D:getetag>${escapedEtag}</D:getetag>
        <D:getlastmodified>${escapedLastmodified}</D:getlastmodified>
        <D:resourcetype>${collectionTag}</D:resourcetype>
      </D:prop>
      <D:status>HTTP/1.1 200 OK</D:status>
    </D:propstat>
  </D:response>`;
}

/**
 * 生成完整的 PROPFIND multistatus 响应
 * @param requestUrl - 客户端请求的完整 URL（用于构建响应中的 href）
 * @param basePath - 当前列出的基础路径（与请求 URL 对应）
 * @param props - 属性数组
 * @returns XML 字符串
 */
export function generatePropfindResponse(requestUrl: string, basePath: string, props: WebDAVProps[]): string {
  // 移除请求 URL 中的查询参数，只保留路径部分
  const url = new URL(requestUrl);
  const baseUrl = url.pathname.endsWith('/') ? url.pathname : url.pathname + '/';

  const responses = props.map(prop => {
    // 构建资源的完整路径（相对于存储桶根）
    let resourcePath = basePath;
    if (prop.displayname) {
      // 如果 basePath 为空，直接使用 displayname；否则拼接
      resourcePath = basePath ? `${basePath}/${prop.displayname}` : prop.displayname;
    }
    // 处理目录：确保路径以 / 结尾
    if (prop.resourcetype === 'collection' && resourcePath && !resourcePath.endsWith('/')) {
      resourcePath += '/';
    }
    return generatePropResponse(baseUrl, resourcePath, prop);
  }).join('\n');

  return `<?xml version="1.0" encoding="utf-8" ?>
<D:multistatus xmlns:D="DAV:">
${responses}
</D:multistatus>`;
}

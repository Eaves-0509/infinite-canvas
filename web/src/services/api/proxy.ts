/** 将第三方 API 请求通过本站同域代理转发，避免浏览器跨域限制。 */
export function proxiedApiUrl(url: string) {
    return `/api/proxy?url=${encodeURIComponent(url)}`;
}

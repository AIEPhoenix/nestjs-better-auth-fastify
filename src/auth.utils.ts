import type { FastifyRequest, FastifyReply } from 'fastify';

/**
 * Convert Fastify/Node.js headers to Web standard Headers
 *
 * @param headers - Fastify request headers object
 * @returns Web standard Headers object
 *
 * Performance: Uses direct iteration instead of Object.entries()
 *
 * @example
 * ```typescript
 * const headers = toWebHeaders(request.headers);
 * const session = await authService.api.getSession({ headers });
 * ```
 */
export function toWebHeaders(
  headers: Record<string, string | string[] | undefined>,
): Headers {
  const webHeaders = new Headers();

  for (const key in headers) {
    const value = headers[key];
    if (value != null) {
      // Use != to check for both null and undefined
      webHeaders.append(
        key,
        Array.isArray(value) ? value.join(', ') : String(value),
      );
    }
  }

  return webHeaders;
}

/**
 * WebSocket request with handshake headers
 */
interface WebSocketRequest {
  handshake?: {
    headers?: Record<string, string | string[] | undefined>;
  };
}

/**
 * Get headers from Fastify Request (supports WebSocket handshake)
 *
 * @param request - Fastify request object
 * @returns Headers object
 */
export function getHeadersFromRequest(
  request: FastifyRequest,
): Record<string, string | string[] | undefined> {
  // Fast path: most requests have headers
  if (request.headers) {
    return request.headers;
  }

  // WebSocket fallback
  const wsRequest = request as unknown as WebSocketRequest;
  return wsRequest.handshake?.headers ?? {};
}

/**
 * Get Web standard Headers from Fastify Request
 *
 * @param request - Fastify request object
 * @returns Web standard Headers object
 *
 * @example
 * ```typescript
 * @Get('accounts')
 * async getAccounts(@Req() request: FastifyRequest) {
 *   const headers = getWebHeadersFromRequest(request);
 *   return this.authService.api.listUserAccounts({ headers });
 * }
 * ```
 */
export function getWebHeadersFromRequest(request: FastifyRequest): Headers {
  return toWebHeaders(getHeadersFromRequest(request));
}

/**
 * Build Web standard Request object
 *
 * @param request - Fastify request object
 * @returns Web standard Request object
 */
export function toWebRequest(request: FastifyRequest): Request {
  // 1. Build URL - use template string for performance
  const host = request.headers.host ?? 'localhost';
  const url = `${request.protocol}://${host}${request.url}`;

  // 2. Convert Headers
  const headers = toWebHeaders(request.headers);

  // 3. Handle request body
  const method = request.method;
  let body: string | undefined;

  // Skip body processing for GET/HEAD requests
  if (method !== 'GET' && method !== 'HEAD' && request.body != null) {
    body =
      typeof request.body === 'string'
        ? request.body
        : JSON.stringify(request.body);
  }

  // 4. Build Request
  return new Request(url, {
    method,
    headers,
    body,
  });
}

/**
 * Write Web Response to Fastify Reply
 *
 * Handles different content types appropriately:
 * - JSON: parsed and sent as object
 * - Text: sent as string
 * - Binary: sent as buffer
 *
 * @param response - Web standard Response object
 * @param reply - Fastify Reply object
 */
export async function writeWebResponseToReply(
  response: Response,
  reply: FastifyReply,
): Promise<void> {
  // Set status code
  reply.status(response.status);

  // Set response headers - direct iteration
  response.headers.forEach((value, key) => {
    // Skip content-length as Fastify will calculate it
    if (key.toLowerCase() !== 'content-length') {
      reply.header(key, value);
    }
  });

  // Handle empty body
  if (!response.body) {
    reply.send(null);
    return;
  }

  // Determine how to handle the body based on Content-Type
  const contentType = response.headers.get('content-type') ?? '';

  if (contentType.includes('application/json')) {
    // JSON response - read as text first, then parse
    // This avoids the issue of body being consumed by response.json()
    const text = await response.text();
    try {
      const json: unknown = JSON.parse(text);
      reply.send(json);
    } catch {
      // If JSON parsing fails, send as text
      reply.send(text);
    }
  } else if (
    contentType.includes('text/') ||
    contentType.includes('application/xml') ||
    contentType.includes('application/javascript')
  ) {
    // Text-based response
    const text = await response.text();
    reply.send(text);
  } else {
    // Binary or unknown - send as buffer
    const arrayBuffer = await response.arrayBuffer();
    reply.send(Buffer.from(arrayBuffer));
  }
}

export function normalizeBasePath(basePath: string): string {
  let normalized = basePath;

  if (normalized[0] !== '/') {
    normalized = '/' + normalized;
  }

  if (normalized.length > 1 && normalized[normalized.length - 1] === '/') {
    normalized = normalized.slice(0, -1);
  }

  return normalized;
}

import {
  toWebHeaders,
  getHeadersFromRequest,
  getWebHeadersFromRequest,
  toWebRequest,
  writeWebResponseToReply,
  normalizeBasePath,
  parseStringToArray,
} from '@sapix/nestjs-better-auth-fastify';
import type { FastifyRequest, FastifyReply } from 'fastify';

describe('auth.utils', () => {
  describe('toWebHeaders', () => {
    it('should convert simple headers to Web Headers', () => {
      const headers = {
        'content-type': 'application/json',
        authorization: 'Bearer token123',
      };

      const webHeaders = toWebHeaders(headers);

      expect(webHeaders.get('content-type')).toBe('application/json');
      expect(webHeaders.get('authorization')).toBe('Bearer token123');
    });

    it('should handle array headers by joining with comma', () => {
      const headers = {
        'accept-encoding': ['gzip', 'deflate'],
      };

      const webHeaders = toWebHeaders(headers);

      expect(webHeaders.get('accept-encoding')).toBe('gzip, deflate');
    });

    it('should skip undefined and null values', () => {
      const headers = {
        'content-type': 'application/json',
        'x-undefined': undefined,
        'x-null': null as any,
      };

      const webHeaders = toWebHeaders(headers);

      expect(webHeaders.get('content-type')).toBe('application/json');
      expect(webHeaders.get('x-undefined')).toBeNull();
      expect(webHeaders.get('x-null')).toBeNull();
    });

    it('should convert non-string values to string', () => {
      const headers = {
        'content-length': 123 as any,
      };

      const webHeaders = toWebHeaders(headers);

      expect(webHeaders.get('content-length')).toBe('123');
    });

    it('should handle empty headers object', () => {
      const headers = {};

      const webHeaders = toWebHeaders(headers);

      expect([...webHeaders.entries()]).toHaveLength(0);
    });
  });

  describe('getHeadersFromRequest', () => {
    it('should return request headers', () => {
      const request = {
        headers: {
          'content-type': 'application/json',
          cookie: 'session=abc123',
        },
      } as unknown as FastifyRequest;

      const headers = getHeadersFromRequest(request);

      expect(headers['content-type']).toBe('application/json');
      expect(headers['cookie']).toBe('session=abc123');
    });

    it('should fallback to handshake headers for WebSocket', () => {
      const request = {
        headers: undefined,
        handshake: {
          headers: {
            'x-ws-header': 'ws-value',
          },
        },
      } as unknown as FastifyRequest;

      const headers = getHeadersFromRequest(request);

      expect(headers['x-ws-header']).toBe('ws-value');
    });

    it('should return empty object when no headers available', () => {
      const request = {
        headers: undefined,
      } as unknown as FastifyRequest;

      const headers = getHeadersFromRequest(request);

      expect(headers).toEqual({});
    });
  });

  describe('getWebHeadersFromRequest', () => {
    it('should return Web Headers from request', () => {
      const request = {
        headers: {
          'content-type': 'application/json',
          authorization: 'Bearer token',
        },
      } as unknown as FastifyRequest;

      const webHeaders = getWebHeadersFromRequest(request);

      expect(webHeaders).toBeInstanceOf(Headers);
      expect(webHeaders.get('content-type')).toBe('application/json');
      expect(webHeaders.get('authorization')).toBe('Bearer token');
    });
  });

  describe('toWebRequest', () => {
    it('should create Web Request from Fastify request', () => {
      const request = {
        protocol: 'https',
        url: '/api/auth/session',
        method: 'GET',
        headers: {
          host: 'example.com',
          cookie: 'session=abc123',
        },
        body: undefined,
      } as unknown as FastifyRequest;

      const webRequest = toWebRequest(request);

      expect(webRequest.url).toBe('https://example.com/api/auth/session');
      expect(webRequest.method).toBe('GET');
      expect(webRequest.headers.get('cookie')).toBe('session=abc123');
    });

    it('should use localhost as default host', () => {
      const request = {
        protocol: 'http',
        url: '/api/test',
        method: 'GET',
        headers: {},
        body: undefined,
      } as unknown as FastifyRequest;

      const webRequest = toWebRequest(request);

      expect(webRequest.url).toBe('http://localhost/api/test');
    });

    it('should include JSON body for POST requests', () => {
      const request = {
        protocol: 'https',
        url: '/api/auth/login',
        method: 'POST',
        headers: {
          host: 'example.com',
          'content-type': 'application/json',
        },
        body: { email: 'test@example.com', password: 'secret' },
      } as unknown as FastifyRequest;

      const webRequest = toWebRequest(request);

      expect(webRequest.method).toBe('POST');
      expect(webRequest.body).not.toBeNull();
    });

    it('should include string body for POST requests', () => {
      const request = {
        protocol: 'https',
        url: '/api/auth/login',
        method: 'POST',
        headers: {
          host: 'example.com',
        },
        body: 'raw body content',
      } as unknown as FastifyRequest;

      const webRequest = toWebRequest(request);

      expect(webRequest.body).not.toBeNull();
    });

    it('should not include body for GET requests', () => {
      const request = {
        protocol: 'https',
        url: '/api/test',
        method: 'GET',
        headers: {
          host: 'example.com',
        },
        body: { shouldBeIgnored: true },
      } as unknown as FastifyRequest;

      const webRequest = toWebRequest(request);

      expect(webRequest.body).toBeNull();
    });

    it('should not include body for HEAD requests', () => {
      const request = {
        protocol: 'https',
        url: '/api/test',
        method: 'HEAD',
        headers: {
          host: 'example.com',
        },
        body: { shouldBeIgnored: true },
      } as unknown as FastifyRequest;

      const webRequest = toWebRequest(request);

      expect(webRequest.body).toBeNull();
    });

    it('should use http as default protocol when undefined', () => {
      const request = {
        protocol: undefined,
        url: '/api/test',
        method: 'GET',
        headers: {
          host: 'example.com',
        },
        body: undefined,
      } as unknown as FastifyRequest;

      const webRequest = toWebRequest(request);

      expect(webRequest.url).toBe('http://example.com/api/test');
    });
  });

  describe('writeWebResponseToReply', () => {
    let mockReply: {
      status: jest.Mock;
      header: jest.Mock;
      send: jest.Mock;
    };

    beforeEach(() => {
      mockReply = {
        status: jest.fn().mockReturnThis(),
        header: jest.fn().mockReturnThis(),
        send: jest.fn().mockReturnThis(),
      };
    });

    it('should write status code', async () => {
      const response = new Response(null, { status: 201 });

      await writeWebResponseToReply(
        response,
        mockReply as unknown as FastifyReply,
      );

      expect(mockReply.status).toHaveBeenCalledWith(201);
    });

    it('should write response headers', async () => {
      const response = new Response(null, {
        headers: {
          'content-type': 'application/json',
          'x-custom': 'custom-value',
        },
      });

      await writeWebResponseToReply(
        response,
        mockReply as unknown as FastifyReply,
      );

      expect(mockReply.header).toHaveBeenCalledWith(
        'content-type',
        'application/json',
      );
      expect(mockReply.header).toHaveBeenCalledWith('x-custom', 'custom-value');
    });

    it('should write JSON response body', async () => {
      const response = new Response('{"success": true}', {
        headers: { 'content-type': 'application/json' },
      });

      await writeWebResponseToReply(
        response,
        mockReply as unknown as FastifyReply,
      );

      // Now parses JSON content for application/json content-type
      expect(mockReply.send).toHaveBeenCalledWith({ success: true });
    });

    it('should write text response body', async () => {
      const response = new Response('Hello World', {
        headers: { 'content-type': 'text/plain' },
      });

      await writeWebResponseToReply(
        response,
        mockReply as unknown as FastifyReply,
      );

      expect(mockReply.send).toHaveBeenCalledWith('Hello World');
    });

    it('should send null for empty body', async () => {
      const response = new Response(null);

      await writeWebResponseToReply(
        response,
        mockReply as unknown as FastifyReply,
      );

      expect(mockReply.send).toHaveBeenCalledWith(null);
    });

    it('should fallback to text when JSON parsing fails', async () => {
      const response = new Response('not valid json {{{', {
        headers: { 'content-type': 'application/json' },
      });

      await writeWebResponseToReply(
        response,
        mockReply as unknown as FastifyReply,
      );

      expect(mockReply.send).toHaveBeenCalledWith('not valid json {{{');
    });

    it('should handle binary response body', async () => {
      const binaryData = new Uint8Array([0x48, 0x65, 0x6c, 0x6c, 0x6f]);
      const response = new Response(binaryData, {
        headers: { 'content-type': 'application/octet-stream' },
      });

      await writeWebResponseToReply(
        response,
        mockReply as unknown as FastifyReply,
      );

      expect(mockReply.send).toHaveBeenCalledWith(expect.any(Buffer));
    });

    it('should handle XML response as text', async () => {
      const response = new Response('<root><item>test</item></root>', {
        headers: { 'content-type': 'application/xml' },
      });

      await writeWebResponseToReply(
        response,
        mockReply as unknown as FastifyReply,
      );

      expect(mockReply.send).toHaveBeenCalledWith(
        '<root><item>test</item></root>',
      );
    });

    it('should handle JavaScript response as text', async () => {
      const response = new Response('console.log("hello");', {
        headers: { 'content-type': 'application/javascript' },
      });

      await writeWebResponseToReply(
        response,
        mockReply as unknown as FastifyReply,
      );

      expect(mockReply.send).toHaveBeenCalledWith('console.log("hello");');
    });
  });

  describe('normalizeBasePath', () => {
    it('should keep valid basePath unchanged', () => {
      expect(normalizeBasePath('/api/auth')).toBe('/api/auth');
    });

    it('should add leading slash if missing', () => {
      expect(normalizeBasePath('api/auth')).toBe('/api/auth');
    });

    it('should remove trailing slash', () => {
      expect(normalizeBasePath('/api/auth/')).toBe('/api/auth');
    });

    it('should handle both missing leading and extra trailing slash', () => {
      expect(normalizeBasePath('api/auth/')).toBe('/api/auth');
    });

    it('should handle root path', () => {
      // Root path normalizes to '/' to ensure valid URL construction
      expect(normalizeBasePath('/')).toBe('/');
    });

    it('should handle empty string', () => {
      // Empty string normalizes to '/' for consistency
      expect(normalizeBasePath('')).toBe('/');
    });

    it('should handle multiple trailing slashes', () => {
      expect(normalizeBasePath('/api/auth//')).toBe('/api/auth/');
    });

    it('should preserve nested paths', () => {
      expect(normalizeBasePath('/v1/api/auth')).toBe('/v1/api/auth');
    });
  });

  describe('parseStringToArray', () => {
    it('should parse comma-separated string into array', () => {
      expect(parseStringToArray('admin,user')).toEqual(['admin', 'user']);
    });

    it('should trim whitespace from values', () => {
      expect(parseStringToArray('admin , user , moderator')).toEqual([
        'admin',
        'user',
        'moderator',
      ]);
    });

    it('should return array as-is when given an array', () => {
      expect(parseStringToArray(['admin', 'user'])).toEqual(['admin', 'user']);
    });

    it('should return empty array for undefined', () => {
      expect(parseStringToArray(undefined)).toEqual([]);
    });

    it('should return empty array for empty string', () => {
      expect(parseStringToArray('')).toEqual([]);
    });

    it('should filter out empty values after split', () => {
      expect(parseStringToArray('admin,,user,')).toEqual(['admin', 'user']);
    });

    it('should handle single value', () => {
      expect(parseStringToArray('admin')).toEqual(['admin']);
    });
  });
});

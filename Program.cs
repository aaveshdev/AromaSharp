using System;
using System.Collections.Concurrent;
using System.Collections.Generic;
using System.Diagnostics;
using System.Globalization;
using System.IO;
using System.IO.Compression;
using System.Linq;
using System.Net;
using System.Reflection;
using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using System.Text.RegularExpressions;
using System.Threading;
using System.Threading.Tasks;

namespace AromaSharp
{
    public delegate Task AromaMiddleware(Request req, Response res, Func<Task> next);
    public delegate Task AromaErrorHandler(Exception ex, Request req, Response res);

    public sealed class Request
    {
        internal Request(HttpListenerContext ctx)
        {
            Context = ctx;
            HttpMethod = ctx.Request.HttpMethod.ToUpperInvariant();
            Url = ctx.Request.Url ?? new Uri("http://localhost/");
            Path = Url.AbsolutePath;
            Headers = ctx.Request.Headers;
            RemoteIp = ctx.Request.RemoteEndPoint?.Address.ToString() ?? "";
            Query = QueryString.Parse(Url.Query);
        }

        public HttpListenerContext Context { get; }
        public string HttpMethod { get; internal set; }
        public Uri Url { get; }
        public string Path { get; internal set; }
        public System.Collections.Specialized.NameValueCollection Headers { get; }
        public string RemoteIp { get; }

        public Dictionary<string, string> Params { get; internal set; } = new();
        public Dictionary<string, string> Query { get; internal set; } = new();
        public Dictionary<string, string> Cookies { get; internal set; } = new();

        public string? RawBody { get; internal set; }
        public Dictionary<string, object> Body { get; internal set; } = new();

        public Stream InputStream => Context.Request.InputStream;
        public string ContentType => Context.Request.ContentType ?? string.Empty;
        public long ContentLength64 => Context.Request.ContentLength64;
    }

    public sealed class Response
    {
        internal Response(HttpListenerContext ctx)
        {
            Context = ctx;
            StatusCode = 200;
        }

        public HttpListenerContext Context { get; }
        public int StatusCode { get; private set; }
        public bool Ended { get; private set; }

        public Response status(int code)
        {
            StatusCode = code;
            return this;
        }

        public void setHeader(string name, string value)
        {
            Context.Response.Headers[name] = value;
            
        }

      

        public Task json(object data)
        {
            if (Ended) return Task.CompletedTask;
            var json = JsonSerializer.Serialize(data, new JsonSerializerOptions { WriteIndented = false });
            var bytes = Encoding.UTF8.GetBytes(json);
            Context.Response.StatusCode = StatusCode;
            Context.Response.ContentType = "application/json; charset=utf-8";
            Context.Response.ContentLength64 = bytes.LongLength;
            return end(bytes);
        }

        public Task send(string text)
        {
            if (Ended) return Task.CompletedTask;
            var bytes = Encoding.UTF8.GetBytes(text);
            Context.Response.StatusCode = StatusCode;
            if (string.IsNullOrEmpty(Context.Response.ContentType))
                Context.Response.ContentType = "text/plain; charset=utf-8";
            Context.Response.ContentLength64 = bytes.LongLength;
            return end(bytes);
        }

        public Task send(byte[] data, string contentType)
        {
            if (Ended) return Task.CompletedTask;
            Context.Response.StatusCode = StatusCode;
            Context.Response.ContentType = contentType;
            Context.Response.ContentLength64 = data.LongLength;
            return end(data);
        }

        public Task redirect(string url) => redirect(302, url);

        public Task redirect(int statusVal, string url)
        {
            if (string.IsNullOrWhiteSpace(url))
            {
                status(500);
                return send("Redirect URL not provided");
            }
            status(statusVal);
            setHeader("Location", url);
            Context.Response.RedirectLocation = url;
            Context.Response.StatusCode = StatusCode;
            Ended = true;
            try { Context.Response.OutputStream.Close(); } catch { }
            return Task.CompletedTask;
        }

        public void cookie(string name, string value, CookieOptions? options = null)
        {
            options ??= new CookieOptions();
            var cookie = new Cookie(name, value)
            {
                HttpOnly = options.HttpOnly,
                Secure = options.Secure,
                Path = options.Path,
                Expires = options.Expires ?? DateTime.MinValue
            };
            Context.Response.Cookies.Add(cookie);
        }

        private Task end(byte[] payload)
        {
            Ended = true;
            try
            {
                Context.Response.OutputStream.Write(payload, 0, payload.Length);
                Context.Response.OutputStream.Flush();
            }
            finally
            {
                try { Context.Response.OutputStream.Close(); } catch { }
            }
            return Task.CompletedTask;
        }
    }

    public sealed class CookieOptions
    {
        public bool HttpOnly { get; set; } = true;
        public bool Secure { get; set; } = false;
        public string Path { get; set; } = "/";
        public DateTime? Expires { get; set; }
    }

    internal static class QueryString
    {
        public static Dictionary<string, string> Parse(string? query)
        {
            var dict = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            if (string.IsNullOrEmpty(query)) return dict;
            var q = query.StartsWith("?") ? query.Substring(1) : query;
            var pairs = q.Split('&', StringSplitOptions.RemoveEmptyEntries);
            foreach (var pair in pairs)
            {
                var kv = pair.Split('=', 2);
                var key = Uri.UnescapeDataString(kv[0].Replace('+', ' '));
                var val = kv.Length > 1 ? Uri.UnescapeDataString(kv[1].Replace('+', ' ')) : "";
                dict[key] = val;
            }
            return dict;
        }
    }


    internal sealed class Route
    {
        public string Method { get; set; } = "GET";
        public Regex PathRegex { get; set; } = new Regex("^/$");
        public List<string> ParamNames { get; set; } = new();
        public Func<Request, Response, Task> Handler { get; set; } = (_, __) => Task.CompletedTask;
    }

    public class Router
    {
        internal readonly List<Route> routes = new();
        internal readonly List<AromaMiddleware> middlewares = new();

        public void use(AromaMiddleware middleware) => middlewares.Add(middleware);

        public void use(string path, Router router)
        {
            middlewares.Add(async (req, res, next) =>
            {
                var original = req.Path;
                if (req.Path.StartsWith(path, StringComparison.OrdinalIgnoreCase))
                {
                    req.Path = req.Path.Substring(path.Length);
                    if (string.IsNullOrEmpty(req.Path)) req.Path = "/";
                    await Aroma.ProcessMiddlewares(router.middlewares, req, res, router.routes);
                    var r = Aroma.MatchRoute(router.routes, req);
                    if (r != null) await r.Handler(req, res); else await next();
                }
                else
                {
                    await next();
                }
                req.Path = original;
            });
        }

        public void use(object middleware)
        {
            if (middleware is AromaMiddleware m) middlewares.Add(m);
            else throw new InvalidOperationException("Invalid middleware");
        }

        public void get(string path, params AromaMiddleware[] handlers) => route("GET", path, handlers);
        public void post(string path, params AromaMiddleware[] handlers) => route("POST", path, handlers);
        public void put(string path, params AromaMiddleware[] handlers) => route("PUT", path, handlers);
        public void delete(string path, params AromaMiddleware[] handlers) => route("DELETE", path, handlers);
        public void all(string path, params AromaMiddleware[] handlers) => route("*", path, handlers);

        private void route(string method, string path, params AromaMiddleware[] handlers)
        {
            var (regex, names) = Aroma.BuildPathRegex(path);
            routes.Add(new Route
            {
                Method = method.ToUpperInvariant(),
                PathRegex = regex,
                ParamNames = names,
                Handler = async (req, res) =>
                {
                    var index = 0;
                    async Task Next()
                    {
                        if (index < handlers.Length)
                        {
                            var h = handlers[index++];
                            await h(req, res, Next);
                        }
                    }
                    await Next();
                }
            });
        }

        //public void rateLimiter(RateLimiterOptions options) => this.use(RateLimiterMain.Middleware(options));
        //public void logger() => this.use(LoggerMain.Middleware());
    }

    public class Aroma : Router
    {
        internal readonly List<AromaMiddleware> rootMiddlewares = new();
        internal readonly List<AromaErrorHandler> errorHandlers = new();
        internal readonly Dictionary<string, object?> settings = new();

        private readonly Stopwatch uptime = Stopwatch.StartNew();
        private readonly SessionStore sessionStore = new();
        private readonly List<string> staticRoots = new();

        private long requestCount = 0;
        private HttpListener? listener;
        private CancellationTokenSource? cts;

        public void set(string key, object? value) => settings[key] = value;
        public object? get(string key) => settings.TryGetValue(key, out var v) ? v : null;

        public new void use(AromaMiddleware middleware) => rootMiddlewares.Add(middleware);

        public new void use(string path, Router router)
        {
            rootMiddlewares.Add(async (req, res, next) =>
            {
                var original = req.Path;
                if (req.Path.StartsWith(path, StringComparison.OrdinalIgnoreCase))
                {
                    req.Path = req.Path.Substring(path.Length);
                    if (string.IsNullOrEmpty(req.Path)) req.Path = "/";
                    await ProcessMiddlewares(router.middlewares, req, res, router.routes, true);
                    var r = MatchRoute(router.routes, req);
                    if (r != null) await r.Handler(req, res); else await next();
                }
                else
                {
                    await next();
                }
                req.Path = original;
            });
        }

        public void handleErrors(AromaErrorHandler handler) => errorHandlers.Add(handler);

        public void serveStatic(string directory)
        {
            if (!Directory.Exists(directory)) throw new DirectoryNotFoundException(directory);
            staticRoots.Add(Path.GetFullPath(directory));
        }

        public void enableTemplateEngine() {}

        public void useSessions() {  }
        public void useCookies() {  }
        public void parseBody()
        {
            this.use(async (req, res, next) =>
            {
                await BodyParser.EnsureParsedAsync(req);
                await next();
            });
        }

        public void rateLimiter(RateLimiterOptions options) => this.use(RateLimiterMain.Middleware(options));
        public void logger() => this.use(LoggerMain.Middleware());

        public Task render(Response res, string viewPath, Dictionary<string, object?> data)
        {
            var html = File.ReadAllText(viewPath);
            var rendered = TemplateEngine.render(html, data);
            return res.send(rendered);
        }

        public void metrics(string path = "/metrics")
        {
            get(path, async (req, res, next) =>
            {
                var mem = GC.GetTotalMemory(false);
                await res.json(new
                {
                    status = "ok",
                    uptime = uptime.Elapsed.TotalSeconds,
                    memory = new { bytes = mem },
                    requests = Interlocked.Read(ref requestCount),
                    timestamp = DateTime.UtcNow
                });
            });
        }

        public void mount(string directory)
        {
            if (!Directory.Exists(directory)) return;
            foreach (var dll in Directory.EnumerateFiles(directory, "*.dll"))
            {
                try
                {
                    var asm = Assembly.LoadFrom(dll);
                    foreach (var t in asm.GetTypes().Where(t => typeof(IAromaModule).IsAssignableFrom(t) && !t.IsAbstract))
                    {
                        var mod = (IAromaModule?)Activator.CreateInstance(t);
                        mod?.Register(this);
                    }
                }
                catch {  }
            }
        }

        public void listen(int port, Action? started = null)
        {
            listener = new HttpListener();
       
            listener.Prefixes.Add($"http://localhost:{port}/");
            listener.Start();
            cts = new CancellationTokenSource();
            started?.Invoke();

                while (!cts.IsCancellationRequested)
                {
                    HttpListenerContext ctx;
                
                    try { ctx = listener.GetContext(); }
                    catch when (cts.IsCancellationRequested) { break; }
                    catch {continue; }
                    _ = HandleRequest(ctx);
                }
            
        }

        public void Stop()
        {
            try { cts?.Cancel(); } catch { }
            try { listener?.Stop(); } catch { }
        }

        private async Task HandleRequest(HttpListenerContext ctx)
        {
            Interlocked.Increment(ref requestCount);
            var req = new Request(ctx);
            var res = new Response(ctx);
            
            if (!(settings.TryGetValue("x-powered-by", out var v) && v is bool b && b == false))
            {
                res.setHeader("X-Powered-By", $"Aroma.net/{GetVersion()}");
            }

            foreach (Cookie c in ctx.Request.Cookies)
                req.Cookies[c.Name] = c.Value;

            try
            {
                await ProcessMiddlewares(rootMiddlewares, req, res, routes);

                if (!res.Ended && staticRoots.Count > 0)
                {
                    if (await TryServeStatic(req, res)) return;
                }

               
                var route = MatchRoute(routes, req);
                if (route != null && !res.Ended)
                {
                    
                    var match = route.PathRegex.Match(req.Path);
                    if (match.Success)
                    {
                        req.Params = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
                        for (int i = 0; i < route.ParamNames.Count; i++)
                        {
                            var val = Uri.UnescapeDataString(match.Groups[i + 1].Value);
                            req.Params[route.ParamNames[i]] = val;
                        }
                    }
                    await route.Handler(req, res);
                }
                else if (!res.Ended)
                {
                    if (settings.TryGetValue("404", out var four) && four is Func<Request, Response, Task> h404)
                    {
                        await h404(req, res);
                    }
                    else
                    {
                        res.status(404);
                        await res.send("404 Not Found");
                    }
                }
            }
            catch (Exception ex)
            {
                await ProcessErrorHandlers(errorHandlers, ex, req, res);
            }
        }

        internal static (Regex regex, List<string> names) BuildPathRegex(string path)
        {
            // Convert /users/:id/profile/* -> ^/users/([^/]+)/profile/.*
            var isWildcard = path.EndsWith("*");
            var paramRegex = new Regex(":([^/]+)");
            var names = new List<string>();
            string pattern = paramRegex.Replace(path, m =>
            {
                names.Add(m.Groups[1].Value);
                return "([^/]+)";
            });
            if (isWildcard)
            {
                pattern = pattern.Substring(0, pattern.Length - 1) + ".*";
                return (new Regex("^" + pattern, RegexOptions.IgnoreCase | RegexOptions.Compiled), names);
            }
            else
            {
                return (new Regex("^" + pattern + "$", RegexOptions.IgnoreCase | RegexOptions.Compiled), names);
            }
        }

        internal static Route? MatchRoute(List<Route> routes, Request req)
        {
            foreach (var r in routes)
            {
                if (r.Method != "*" && !string.Equals(r.Method, req.HttpMethod, StringComparison.OrdinalIgnoreCase))
                    continue;
                var m = r.PathRegex.Match(req.Path);
                if (m.Success) return r;
            }
            return null;
        }

        internal static async Task ProcessMiddlewares(List<AromaMiddleware> middlewares, Request req, Response res, List<Route> routes, bool isNested = false)
        {
            int index = 0;
            async Task Next()
            {
                if (index < middlewares.Count)
                {
                    var h = middlewares[index++];
                    await h(req, res, Next);
                }
            }
            await Next();
        }

        internal static async Task ProcessErrorHandlers(List<AromaErrorHandler> handlers, Exception ex, Request req, Response res)
        {
            if (handlers.Count == 0)
            {
                try
                {
                    res.status(500);
                    await res.send("Internal Server Error");
                }
                catch { }
                return;
            }
            foreach (var h in handlers)
            {
                try { await h(ex, req, res); }
                catch { /* swallow to try next */ }
                if (res.Ended) return;
            }
            if (!res.Ended)
            {
                res.status(500);
                await res.send("Internal Server Error");
            }
        }

        private static string GetVersion()
        {
            var v = typeof(Aroma).Assembly.GetName().Version;
            return v != null ? v.ToString() : "1.0.0";
        }

        private async Task<bool> TryServeStatic(Request req, Response res)
        {
            foreach (var root in staticRoots)
            {
                var rel = req.Path.TrimStart('/').Replace('/', Path.DirectorySeparatorChar);
                var file = Path.Combine(root, rel);
                if (File.Exists(file))
                {
                    var data = await File.ReadAllBytesAsync(file);
                    var mime = MimeTypes.GetMimeType(Path.GetExtension(file));
                    await res.send(data, mime);
                    return true;
                }
            }
            return false;
        }
    }

   

    internal sealed class SessionStore
    {
        private readonly ConcurrentDictionary<string, Dictionary<string, object>> store = new();


        public string GetOrCreateSessionId(Request req, Response res)
        {
            if (req.Cookies.TryGetValue("AROMA.SID", out var sid) && !string.IsNullOrWhiteSpace(sid))
            {
                store.TryAdd(sid, new Dictionary<string, object>());
                return sid;
            }
            sid = GenerateId();
            store.TryAdd(sid, new Dictionary<string, object>());
            res.cookie("AROMA.SID", sid, new CookieOptions { HttpOnly = true, Path = "/" });
            return sid;
        }

        public Dictionary<string, object> Get(string sid) => store.GetOrAdd(sid, _ => new Dictionary<string, object>());

        private static string GenerateId()
        {
            var bytes = new byte[16];
            RandomNumberGenerator.Fill(bytes);
            return Convert.ToHexString(bytes).ToLowerInvariant();
        }
    }

   

    public static class LoggerMain
    {
        public static AromaMiddleware Middleware() => async (req, res, next) =>
        {
            var sw = Stopwatch.StartNew();
            await next();
            sw.Stop();
            Console.WriteLine($"[{DateTime.Now:HH:mm:ss}] {req.HttpMethod} {req.Path} -> {res.Context.Response.StatusCode} ({sw.ElapsedMilliseconds} ms)");
        };
    }

    public sealed class RateLimiterOptions
    {
        public int Requests { get; set; } = 100; 
        public TimeSpan Window { get; set; } = TimeSpan.FromMinutes(1);
        public string IdentifierHeader { get; set; } = "X-Forwarded-For";
    }

    public static class RateLimiterMain
    {
        private class Bucket { public int Count; public DateTime ResetAt; }
        private static readonly ConcurrentDictionary<string, Bucket> buckets = new();

        public static AromaMiddleware Middleware(RateLimiterOptions options) => async (req, res, next) =>
        {
            var id = req.Headers[options.IdentifierHeader] ?? req.RemoteIp;
            var now = DateTime.UtcNow;
            var b = buckets.GetOrAdd(id, _ => new Bucket { Count = 0, ResetAt = now.Add(options.Window) });
            lock (b)
            {
                if (now >= b.ResetAt)
                {
                    b.Count = 0;
                    b.ResetAt = now.Add(options.Window);
                }
                b.Count++;
                res.setHeader("X-RateLimit-Remaining", Math.Max(0, options.Requests - b.Count).ToString(CultureInfo.InvariantCulture));
                res.setHeader("X-RateLimit-Reset", ((long)(b.ResetAt - now).TotalSeconds).ToString(CultureInfo.InvariantCulture));
                if (b.Count > options.Requests)
                {
                    res.status(429);
                    _ = res.send("Too Many Requests");
                    return;
                }
            }
            await next();
        };
    }

    public static class TemplateEngine
    {
        private static readonly Regex Token = new(@"\{\{\s*([A-Za-z0-9_\.]+)\s*\}\}", RegexOptions.Compiled);

        public static string render(string template, IDictionary<string, object?> data)
        {
            return Token.Replace(template, m =>
            {
                var path = m.Groups[1].Value.Split('.');
                object? current = data;
                foreach (var part in path)
                {
                    if (current is IDictionary<string, object?> dict && dict.TryGetValue(part, out var v))
                        current = v;
                    else { current = null; break; }
                }
                return current?.ToString() ?? string.Empty;
            });
        }
    }

    public static class MimeTypes
    {
        private static readonly Dictionary<string, string> map = new(StringComparer.OrdinalIgnoreCase)
        {
            [".html"] = "text/html; charset=utf-8",
            [".htm"] = "text/html; charset=utf-8",
            [".css"] = "text/css; charset=utf-8",
            [".js"] = "application/javascript; charset=utf-8",
            [".json"] = "application/json; charset=utf-8",
            [".png"] = "image/png",
            [".jpg"] = "image/jpeg",
            [".jpeg"] = "image/jpeg",
            [".gif"] = "image/gif",
            [".svg"] = "image/svg+xml",
            [".txt"] = "text/plain; charset=utf-8",
            [".ico"] = "image/x-icon",
            [".woff"] = "font/woff",
            [".woff2"] = "font/woff2",
        };

        public static string GetMimeType(string ext) => map.TryGetValue(ext, out var v) ? v : "application/octet-stream";
    }

    public static class BodyParser
    {
        public static async Task EnsureParsedAsync(Request req)
        {
            if (req.RawBody != null) return;
            if (req.ContentLength64 <= 0) { req.RawBody = string.Empty; return; }

            using var ms = new MemoryStream();
            await req.InputStream.CopyToAsync(ms);
            var bytes = ms.ToArray();
            req.RawBody = Encoding.UTF8.GetString(bytes);

            var ct = req.ContentType.ToLowerInvariant();
            if (ct.Contains("application/json"))
            {
                try
                {
                    var doc = JsonSerializer.Deserialize<Dictionary<string, object>>(req.RawBody);
                    if (doc != null) req.Body = doc;
                }
                catch { /* ignore */ }
            }
            else if (ct.Contains("application/x-www-form-urlencoded"))
            {
                var dict = QueryString.Parse(req.RawBody);
                req.Body = dict.ToDictionary(kvp => kvp.Key, kvp => (object)kvp.Value);
            }
          
        }
    }

    public interface IAromaModule { void Register(Aroma app); }

   
}




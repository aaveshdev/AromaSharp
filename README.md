# AromaSharp — Lightweight C# Web Framework

AromaSharp is a small, expressive web framework for .NET inspired by the simplicity of microframeworks.  
It provides an Express and Aroma.js like API for routing, middleware, static files, simple templating, sessions, and body parsing — all in a single minimal library you can reference in your projects.

---

## Features

- `get`, `post`, `put`, `delete`, `all` route helpers
- Middleware pipeline with `use(...)`
- `parseBody()` middleware to populate `req.Body` (JSON & form-urlencoded)
- Rate limiter and logger middlewares
- Module mounting from DLLs (`mount(...)`)

---

---

## Quick start

Example `Program.cs` using AromaSharp API:

```csharp
using System;
using AromaSharp;

class Program
{
    static void Main(string[] args)
    {
        var app = new Aroma();

        // Enable body parsing middleware so req.body is available in POST handlers
        app.parseBody();

        // Log all requests
        app.logger();

        // Simple GET
        app.get("/", async (req, res, next) =>
        {
            await res.send("Hello from AromaSharp!");
        });

        // POST that expects JSON or form data
        app.post("/echo", async (req, res, next) =>
        {
            // req.body will be populated by parseBody() middleware
            await res.json(new { received = req.body, query = req.query });
        });

        // Start listening (blocks the thread)
        app.listen(5000, () => Console.WriteLine("AromaSharp running at http://localhost:5000"));
    }
}
```

---

## API Reference (selected)

### `Aroma` (main app)

- `new Aroma()` — create app instance
- `use(middleware)` — add middleware: `async (req, res, next) => { ...; await next(); }`
- `use(path, router)` — mount sub-router at path
- `get/post/put/delete/all(path, handlers...)` — register routes
- `parseBody()` — enable automatic parsing of JSON or `application/x-www-form-urlencoded`
- `serveStatic(directory)` — serve files from directory
- `mount(directory)` — load `.dll` modules implementing `IAromaModule`
- `logger()` — attach request logger middleware
- `rateLimiter(options)` — attach rate limiter middleware
- `listen(port, started)` — start server (blocking)
- `stop()` — stop server

### `Request req`

- `req.Path`, `req.Url`, `req.HttpMethod`
- `req.Query` — query string dictionary
- `req.Params` — route params from `:param` style routes
- `req.Body` — populated by `parseBody()` (Dictionary<string, object> for JSON/form)
- `req.Cookies` — cookie dictionary

### `Response res`

- `res.status(code)` — set status code (returns `res`)
- `res.setHeader(name, value)` — set header
- `res.send(string)` / `res.send(byte[], contentType)` — write body
- `res.json(object)` — serialize to JSON and send
- `res.redirect(url)` / `res.redirect(status, url)`
- `res.cookie(name, value, options)` — set cookie

---

## Body parsing

Call `app.parseBody()` once during setup and all route handlers will have `req.body` populated for requests with:

- `Content-Type: application/json` (deserializes to `Dictionary<string, object>`)
- `Content-Type: application/x-www-form-urlencoded` (parsed into `Dictionary<string, object>`)

Example client request JSON:

```json
{
  "name": "Aavesh",
  "email": "aavesh@example.com"
}
```

In your handler:

```csharp
var name = req.body["name"] : null;
```

---

## Contributing

Contributions welcome — open an issue or PR for enhancements (routing features, multipart parser, template improvements, etc.).

---

## License

MIT © AromaSharp contributors

const assert = require("node:assert/strict");
const { test } = require("node:test");
const mongoose = require("mongoose");
const { app, startServer } = require("../server.js");
const connectDB = require("../config/db.js");

test("the API waits for MongoDB before opening its HTTP listener", async (t) => {
  let resolveConnection;
  t.mock.method(mongoose, "connect", () => new Promise((resolve) => {
    resolveConnection = resolve;
  }));
  t.mock.method(console, "log", () => {});
  const server = {};
  const listen = t.mock.method(app, "listen", () => server);

  const startup = startServer();
  assert.equal(listen.mock.callCount(), 0);
  resolveConnection({ connection: { host: "test-host" } });
  assert.equal(await startup, server);
  assert.equal(listen.mock.callCount(), 1);
});

test("a failed TLS handshake prevents HTTP startup and gives troubleshooting guidance", async (t) => {
  t.mock.method(mongoose, "connect", async () => {
    throw new Error("tlsv1 alert internal error: SSL alert number 80");
  });
  const listen = t.mock.method(app, "listen", () => {});

  await assert.rejects(startServer(), (error) => {
    assert.match(error.message, /MongoDB connection failed/);
    assert.match(error.message, /Network Access IP access list/);
    assert.match(error.message, /27017/);
    return true;
  });
  assert.equal(listen.mock.callCount(), 0);
});

test("missing MONGO_URI fails before contacting MongoDB", async (t) => {
  const originalUri = process.env.MONGO_URI;
  t.after(() => {
    if (originalUri === undefined) delete process.env.MONGO_URI;
    else process.env.MONGO_URI = originalUri;
  });
  process.env.MONGO_URI = " ";
  const connect = t.mock.method(mongoose, "connect", () => {});
  await assert.rejects(connectDB(), /MONGO_URI is missing/);
  assert.equal(connect.mock.callCount(), 0);
});

test("connection failures redact MongoDB credentials from the displayed error", async (t) => {
  t.mock.method(mongoose, "connect", async () => {
    throw new Error("Failed to connect to mongodb+srv://example-user:private-password@cluster.example/test");
  });
  await assert.rejects(connectDB(), (error) => {
    assert.match(error.message, /\[redacted MongoDB URI\]/);
    assert.doesNotMatch(error.message, /example-user|private-password/);
    return true;
  });
});

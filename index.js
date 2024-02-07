const fastify = require("fastify")({ logger: true });
const path = require("path");
const bcrypt = require("bcrypt");
const SQL = require("sql-template-strings");

fastify.register(require("@fastify/static"), {
  root: path.join(__dirname, "Gp"),
});

fastify.register(require("@fastify/cors"), {
  origin: "*",
  methods: ["GET", "POST"],
});

fastify.register(require("@fastify/jwt"), {
  secret: "supersecret",
});

fastify.register(require("fastify-sqlite"), {
  dbFile: "./db.sqlite",
  promiseApi: true,
});

fastify.decorate("authenticate", async function (request, reply) {
  try {
    await request.jwtVerify();
  } catch (err) {
    reply.send(err);
  }
});

fastify.get("/", async (request, reply) => {
  reply.redirect("/index.html");
});

fastify.get(
  "/whoami",
  {
    onRequest: [fastify.authenticate],
  },
  async (request, reply) => {
    return request.user;
  }
);

fastify.post(
  "/booking",
  {
    onRequest: [fastify.authenticate],
  },
  async (request, reply) => {
    const { adults, children, seniors, students, checkin_date, checkout_date } =
      request.body;

    const user_id = request.user.id;

    try {
      await fastify.sqlite.run(
        SQL`INSERT INTO bookings (user_id, adults, children, seniors, students, checkin_date, checkout_date) VALUES (${user_id}, ${adults}, ${children}, ${seniors}, ${students}, ${checkin_date}, ${checkout_date})`
      );
    } catch (error) {
      if (
        error.code === `SQLITE_CONSTRAINT` &&
        error.message.includes(`UNIQUE`)
      ) {
        return reply.status(409).send({ message: "Booking already exists" });
      }

      throw error;
    }
  }
);

fastify.post("/login", async (request, reply) => {
  const { email, password } = request.body;
  const user = await fastify.sqlite.get(SQL`
      SELECT id, password_hash FROM users WHERE email = ${email}
    `);
  if (typeof user === `undefined`) {
    return reply.status(401).send({ message: "Email has no associated user" });
  }
  const isPasswordValid = await validatePassword(password, user.password_hash);
  if (!isPasswordValid) {
    return reply.status(401).send({ message: "Incorrect password" });
  }

  const token = fastify.jwt.sign({ id: user.id });
  return { token };
});

fastify.post("/register", async (request, reply) => {
  const { email, password, first_name, last_name } = request.body;

  const passwordHash = await hashPassword(password);

  try {
    await fastify.sqlite.run(
      SQL`INSERT INTO users (email, password_hash, first_name, last_name) VALUES (${email}, ${passwordHash}, ${first_name}, ${last_name})`
    );
  } catch (error) {
    if (
      error.code === `SQLITE_CONSTRAINT` &&
      error.message.includes(`UNIQUE`)
    ) {
      return reply.status(409).send({ message: "Email already in use" });
    }

    throw error;
  }

  const id = await fastify.sqlite.get(
    SQL`SELECT id FROM users WHERE email = ${email}`
  );

  const token = fastify.jwt.sign({ id });

  return { token };
});

// fastify.addHook("onRequest", async (request, reply) => {
//   if (!request.url.endsWith(".html")) {
//     reply.redirect(301, request.url + ".html");
//   }
// });

fastify.listen({ port: 3000 }, (err) => {
  if (err) {
    fastify.log.error(err);
    process.exit(1);
  }
});

async function hashPassword(password) {
  return await bcrypt.hash(password, 10);
}

async function validatePassword(password, hashedPassword) {
  return await bcrypt.compare(password, hashedPassword);
}

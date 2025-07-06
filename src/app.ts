//src/app.ts
import express from "express";
import cors from "cors";
import helmet from "helmet";
import { errorHandler } from "./middleware/error";
import { requestLogger } from "./middleware/logger";
import routes from "./routes";

const app = express();

app.use(helmet());
app.use(cors());
app.use(express.json());
app.use(express.urlencoded({ extended: true }));
app.use(requestLogger);

app.use("/api", routes);

app.get("/health", (req, res) => {
  res.status(200).json({ status: "OK" });
});

app.use(errorHandler);

export default app;

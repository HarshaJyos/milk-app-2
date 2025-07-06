//src/middleware/logger.ts
import { Request, Response, NextFunction } from "express";
import { logger } from "../utils/logger";

export const requestLogger = (
  req: Request,
  _res: Response,
  next: NextFunction
) => {
  logger.info(`${req.method} ${req.url}`, {
    ip: req.ip,
    query: req.query,
    body: req.body,
  });
  next();
};

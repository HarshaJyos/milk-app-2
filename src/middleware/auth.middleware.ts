import { Request, Response, NextFunction } from "express";
import jwt from "jsonwebtoken";
import { StatusCodes } from "http-status-codes";
import { redisClient } from "../config/redis";
import { config } from "../config";
import { logger } from "../utils/logger";

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    role: "customer" | "vendor" | "admin" | "super_admin";
  };
}

// Validate JWT
export const authenticateJWT = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  const authHeader = req.headers.authorization;
  if (!authHeader || !authHeader.startsWith("Bearer ")) {
    res.status(StatusCodes.UNAUTHORIZED).json({
      success: false,
      error: "No token provided",
    });
    return;
  }

  const token = authHeader.split(" ")[1];
  try {
    const decoded = jwt.verify(token, config.jwt.secret as string) as {
      id: string;
      role: "customer" | "vendor" | "admin" | "super_admin";
    };
    const sessionKey = `session:${decoded.role}:${decoded.id}`;
    const session = await redisClient.get(sessionKey);

    if (!session || session !== token) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Invalid or expired session",
      });
      return;
    }

    req.user = {
      id: decoded.id,
      role: decoded.role,
    };
    next();
  } catch (error) {
    logger.error("JWT validation error:", error);
    res.status(StatusCodes.UNAUTHORIZED).json({
      success: false,
      error: "Invalid token",
    });
  }
};

// Role-based access control
export const restrictTo = (...roles: string[]) => {
  return (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): void => {
    if (!req.user || !roles.includes(req.user.role)) {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Access denied",
      });
      return;
    }
    next();
  };
};

// Rate limiting for OTP and login
export const rateLimit = (
  type: "otp" | "login",
  limit: number,
  windowMs: number
) => {
  return async (
    req: Request,
    res: Response,
    next: NextFunction
  ): Promise<void> => {
    const key = `rate:${type}:${req.ip}`;
    const current = await redisClient.get(key);
    const count = current ? parseInt(current) : 0;

    if (count >= limit) {
      res.status(StatusCodes.TOO_MANY_REQUESTS).json({
        success: false,
        error: "Too many requests, try again later",
      });
      return;
    }

    await redisClient.setEx(key, windowMs / 1000, (count + 1).toString());
    next();
  };
};

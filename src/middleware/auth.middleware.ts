//src/middleware/auth.middleware.ts
import { Request, Response, NextFunction } from "express";
import { StatusCodes } from "http-status-codes";
import jwt from "jsonwebtoken";
import { redisClient } from "../config/redis";
import { config } from "../config";
import { logger } from "../utils/logger";
import { CustomerModel, VendorModel, AdminModel } from "../models";

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    role: "customer" | "vendor" | "admin" | "super_admin";
  };
}

export const authenticate = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    const token = req.headers.authorization?.split(" ")[1];
    if (!token) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "No token provided",
      });
      return;
    }

    const decoded = jwt.verify(token, config.jwt.secret as string) as {
      id: string;
      role: string;
    };
    const sessionToken = await redisClient.get(
      `session:${decoded.role}:${decoded.id}`
    );
    if (!sessionToken || sessionToken !== token) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Invalid or expired session",
      });
      return;
    }

    let user;
    if (decoded.role === "customer") {
      user = await CustomerModel.findById(decoded.id);
    } else if (decoded.role === "vendor") {
      user = await VendorModel.findById(decoded.id);
    } else {
      user = await AdminModel.findById(decoded.id);
    }

    if (
      !user ||
      (decoded.role === "vendor" && user.status !== "approved") ||
      user.status !== "active"
    ) {
      await redisClient.del(`session:${decoded.role}:${decoded.id}`);
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "User not found or inactive",
      });
      return;
    }

    // Check if token is near expiry (within 10 minutes)
    const { exp } = decoded as any;
    if (exp && Date.now() >= exp * 1000 - 10 * 60 * 1000) {
      const newToken = jwt.sign(
        { id: decoded.id, role: decoded.role },
        config.jwt.secret as string,
        { expiresIn: config.jwt.expiresIn }
      );
      await redisClient.setEx(
        `session:${decoded.role}:${decoded.id}`,
        24 * 60 * 60,
        newToken
      );
      res.setHeader("X-New-Token", newToken);
    }

    req.user = { id: decoded.id, role: decoded.role as any };
    next();
  } catch (error) {
    logger.error("Authentication error:", error);
    res.status(StatusCodes.UNAUTHORIZED).json({
      success: false,
      error: "Invalid token",
    });
  }
};

export const authorize = (roles: string[]) => {
  return (
    req: AuthenticatedRequest,
    res: Response,
    next: NextFunction
  ): void => {
    if (!req.user || !roles.includes(req.user.role)) {
      res.status(StatusCodes.FORBIDDEN).json({
        success: false,
        error: "Insufficient permissions",
      });
      return;
    }
    next();
  };
};

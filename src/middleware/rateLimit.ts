// src/middleware/rateLimit.ts
import { Request, Response, NextFunction } from "express";
import { StatusCodes } from "http-status-codes";
import { redisClient } from "../config/redis";
import { logger } from "../utils/logger";
import { VendorModel, AdminModel } from "../models";

interface AuthenticatedRequest extends Request {
  user?: {
    id: string;
    role: "customer" | "vendor" | "admin" | "super_admin";
  };
}

export const rateLimit = async (
  req: AuthenticatedRequest,
  res: Response,
  next: NextFunction
): Promise<void> => {
  try {
    if (!req.user) {
      res.status(StatusCodes.UNAUTHORIZED).json({
        success: false,
        error: "Unauthorized",
      });
      return;
    }

    const { id, role } = req.user;
    let limit = 1000; // Default limit
    let windowMs = 24 * 60 * 60 * 1000; // 24 hours

    if (role === "vendor") {
      const vendor = await VendorModel.findById(id);
      if (!vendor || vendor.status !== "approved") {
        res.status(StatusCodes.FORBIDDEN).json({
          success: false,
          error: "Vendor not found or not approved",
        });
        return;
      }
      limit = vendor.metadata.apiRateLimit.limit;
      const resetTime =
        vendor.metadata.apiRateLimit.resetAt.getTime() - Date.now();
      windowMs = resetTime > 0 ? resetTime : windowMs; // Ensure positive windowMs
    } else if (["admin", "super_admin"].includes(role)) {
      const admin = await AdminModel.findById(id);
      if (!admin || admin.status !== "active") {
        res.status(StatusCodes.FORBIDDEN).json({
          success: false,
          error: "Admin not found or inactive",
        });
        return;
      }
      limit = 5000; // Higher limit for admins
    }

    const key = `api:rate:${role}:${id}`;

    // Check if key exists and is a valid integer
    const currentValue = await redisClient.get(key);
    if (currentValue !== null && isNaN(parseInt(currentValue))) {
      logger.warn(
        `Invalid Redis value for key ${key}: ${currentValue}. Resetting key.`
      );
      await redisClient.del(key); // Reset corrupted key
    }

    const count = await redisClient.incr(key);
    if (count === 1) {
      const expireSeconds = Math.max(Math.floor(windowMs / 1000), 1); // Ensure positive integer
      await redisClient.expire(key, expireSeconds);
    }

    if (count > limit) {
      res.status(StatusCodes.TOO_MANY_REQUESTS).json({
        success: false,
        error: "Rate limit exceeded",
      });
      return;
    }

    if (role === "vendor") {
      await VendorModel.updateOne(
        { _id: id },
        { "metadata.apiRateLimit.remaining": limit - count }
      );
    }

    next();
  } catch (error) {
    logger.error("Rate limit middleware error:", error);
    res.status(StatusCodes.INTERNAL_SERVER_ERROR).json({
      success: false,
      error: "Internal server error",
    });
  }
};

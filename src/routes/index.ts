// src/routes/index.ts
import { Router } from "express";
import authRoutes from "./auth.route";
import adminRoutes from "./admin.route";
import productRoutes from "./product.route";

const router = Router();

router.get("/ping", (req, res) => {
  res.json({ message: "Pong" });
});

router.use("/auth", authRoutes);
router.use("/admin", adminRoutes);
router.use("/products", productRoutes);

export default router;

import { Router } from "express";
import authRoutes from "./auth.route";

const router = Router();

router.get("/ping", (req, res) => {
  res.json({ message: "Pong" });
});

router.use("/auth", authRoutes);

export default router;

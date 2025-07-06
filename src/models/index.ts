//src/models/index.ts
import { Schema, model, Document } from "mongoose";
import { z } from "zod";
import {
  Customer,
  Vendor,
  Product,
  Delivery,
  Billing,
  VendorPayout,
  Notification,
  Message,
  Complaint,
  Review,
  Admin,
  AuditLog,
  Analytics,
} from "../types";

// Zod Schemas for Request Validation
export const CustomerZodSchema = z.object({
  mobileNumber: z
    .string()
    .regex(/^\+[0-9]{10,12}$/, "Must be a valid E.164 phone number"),
  name: z.string().min(1, "Name is required"),
  email: z.string().email().optional(),
  address: z.object({
    street: z.string().min(1, "Street is required"),
    city: z.string().min(1, "City is required"),
    state: z.string().min(1, "State is required"),
    postalCode: z.string().min(1, "Postal code is required"),
    coordinates: z.object({
      type: z.literal("Point"),
      coordinates: z.tuple([z.number(), z.number()]),
    }),
    formattedAddress: z.string().optional(),
    deliveryInstructions: z.string().optional(),
  }),
  vendorIds: z.array(z.string().regex(/^[0-9a-fA-F]{24}$/)).optional(),
  deliveryPreferences: z.object({
    timeSlot: z.enum(["morning", "afternoon", "evening"]),
    nonDeliveryDays: z.array(z.date()).optional(),
    vacationPeriods: z
      .array(
        z.object({
          startDate: z.date(),
          endDate: z.date(),
          status: z.enum(["active", "completed", "cancelled"]),
        })
      )
      .optional(),
    preferredProducts: z
      .array(
        z.object({
          productId: z.string().regex(/^[0-9a-fA-F]{24}$/),
          quantity: z.number().min(1),
          frequency: z.enum(["daily", "weekly", "biweekly", "monthly"]),
          subscriptionId: z.string().optional(),
        })
      )
      .optional(),
  }),
  language: z.string().regex(/^[a-z]{2}$/, "Must be a valid ISO 639-1 code"),
  status: z.enum(["active", "inactive", "suspended"]).default("active"),
  metadata: z.object({
    source: z.enum(["qr_scan", "web", "app", "admin"]),
    verificationStatus: z
      .enum(["pending", "verified", "failed"])
      .default("pending"),
    verificationToken: z.string().optional(),
    deviceInfo: z
      .object({
        deviceId: z.string(),
        deviceType: z.enum(["ios", "android", "web"]),
        lastUsed: z.date(),
      })
      .optional(),
    i18n: z.object({
      timezone: z.string(),
      currency: z.string().regex(/^[A-Z]{3}$/, "Must be a valid ISO 4217 code"),
    }),
  }),
});

export const VendorZodSchema = z.object({
  mobileNumber: z
    .string()
    .regex(/^\+[0-9]{10,12}$/, "Must be a valid E.164 phone number"),
  name: z.string().min(1, "Name is required"),
  email: z.string().email("Valid email is required"),
  shop: z.object({
    name: z.string().min(1, "Shop name is required"),
    location: z.object({
      street: z.string().min(1, "Street is required"),
      city: z.string().min(1, "City is required"),
      state: z.string().min(1, "State is required"),
      postalCode: z.string().min(1, "Postal code is required"),
      coordinates: z.object({
        type: z.literal("Point"),
        coordinates: z.tuple([z.number(), z.number()]),
      }),
      deliveryRadiusKm: z.number().min(0),
    }),
    contact: z.string().min(1, "Contact is required"),
    logo: z.string().url().optional(),
    licenseNumber: z.string().optional(),
    taxId: z.string().optional(),
    businessHours: z.array(
      z.object({
        day: z.string(),
        open: z.string(),
        close: z.string(),
      })
    ),
  }),
  uniqueId: z.string().min(1, "Unique ID is required"),
  qrCode: z.object({
    url: z.string().url(),
    generatedAt: z.date(),
    expiresAt: z.date().optional(),
  }),
  deliverySlots: z.array(
    z.object({
      slot: z.enum(["morning", "afternoon", "evening"]),
      cutoffTime: z.string(),
      capacity: z.number().min(0),
    })
  ),
  status: z
    .enum(["pending", "approved", "suspended", "inactive"])
    .default("pending"),
  verification: z.object({
    status: z.enum(["pending", "verified", "rejected"]).default("pending"),
    documents: z.array(
      z.object({
        type: z.enum(["license", "tax", "identity"]),
        url: z.string().url(),
        uploadedAt: z.date(),
        verifiedAt: z.date().optional(),
      })
    ),
  }),
  metadata: z.object({
    onboardingSource: z.enum(["self", "admin", "referral"]),
    rating: z.object({
      average: z.number().min(0).max(5),
      count: z.number().min(0),
    }),
    apiRateLimit: z.object({
      limit: z.number().min(0),
      remaining: z.number().min(0),
      resetAt: z.date(),
    }),
  }),
});

export const ProductZodSchema = z.object({
  vendorId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid vendor ID"),
  name: z.string().min(1, "Name is required"),
  category: z.enum(["milk", "dairy", "groceries", "essentials"]),
  variant: z.string().optional(),
  sku: z.string().min(1, "SKU is required"),
  price: z.object({
    base: z.number().min(0),
    currency: z.string().regex(/^[A-Z]{3}$/, "Must be a valid ISO 4217 code"),
    taxes: z.array(
      z.object({
        type: z.string(),
        rate: z.number().min(0),
        amount: z.number().min(0),
      })
    ),
  }),
  unit: z.string().min(1, "Unit is required"),
  description: z.string().optional(),
  stock: z.object({
    quantity: z.number().min(0),
    lowStockThreshold: z.number().min(0),
    restockDate: z.date().optional(),
  }),
  available: z.boolean().default(true),
  bulkDiscounts: z
    .array(
      z.object({
        minQuantity: z.number().min(1),
        price: z.number().min(0),
        validUntil: z.date().optional(),
      })
    )
    .optional(),
  promotions: z
    .array(
      z.object({
        discountType: z.enum(["percentage", "fixed"]),
        discountValue: z.number().min(0),
        startDate: z.date(),
        endDate: z.date(),
        maxUses: z.number().min(0).optional(),
        usedCount: z.number().min(0).default(0),
        code: z.string().optional(),
      })
    )
    .optional(),
  images: z.array(z.string().url()).optional(),
});

export const DeliveryZodSchema = z.object({
  customerId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid customer ID"),
  vendorId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid vendor ID"),
  productIds: z.array(
    z.object({
      productId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid product ID"),
      quantity: z.number().min(1),
      price: z.number().min(0),
    })
  ),
  totalAmount: z.number().min(0),
  deliveryDate: z.date(),
  timeSlot: z.enum(["morning", "afternoon", "evening"]),
  status: z
    .enum([
      "pending",
      "processing",
      "shipped",
      "delivered",
      "cancelled",
      "skipped",
    ])
    .default("pending"),
  deliveryProof: z
    .object({
      signature: z.string().url().optional(),
      photo: z.string().url().optional(),
      timestamp: z.date(),
    })
    .optional(),
  metadata: z.object({
    orderSource: z.enum(["app", "web", "recurring"]),
    deliveryNotes: z.string().optional(),
    subscriptionId: z.string().optional(),
  }),
});

export const BillingZodSchema = z.object({
  customerId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid customer ID"),
  vendorId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid vendor ID"),
  deliveryIds: z.array(z.string().regex(/^[0-9a-fA-F]{24}$/)),
  totalAmount: z.number().min(0),
  billingPeriod: z.object({
    type: z.enum(["daily", "weekly", "monthly"]),
    startDate: z.date(),
    endDate: z.date(),
  }),
  status: z
    .enum(["pending", "paid", "overdue", "failed", "refunded", "disputed"])
    .default("pending"),
  paymentDetails: z.object({
    method: z.enum(["UPI", "card", "net_banking", "wallet", "subscription"]),
    razorpay: z.object({
      orderId: z.string(),
      paymentId: z.string().optional(),
      signature: z.string().optional(),
      subscriptionId: z.string().optional(),
      status: z.enum([
        "created",
        "authorized",
        "captured",
        "failed",
        "refunded",
      ]),
      amount: z.number().min(0),
      currency: z.string().regex(/^[A-Z]{3}$/),
      receipt: z.string(),
      createdAt: z.date(),
      capturedAt: z.date().optional(),
      refundedAt: z.date().optional(),
      refundDetails: z
        .object({
          refundId: z.string(),
          amount: z.number().min(0),
          status: z.enum(["processed", "pending", "failed"]),
          reason: z.string().optional(),
        })
        .optional(),
      webhookStatus: z.object({
        lastReceived: z.date(),
        events: z.array(
          z.object({
            event: z.string(),
            payload: z.record(z.any()),
            receivedAt: z.date(),
          })
        ),
      }),
    }),
    attempts: z.array(
      z.object({
        timestamp: z.date(),
        status: z.enum(["success", "failed"]),
        errorCode: z.string().optional(),
        errorDescription: z.string().optional(),
      })
    ),
  }),
  invoice: z.object({
    number: z.string(),
    pdfUrl: z.string().url().optional(),
    generatedAt: z.date(),
  }),
});

export const VendorPayoutZodSchema = z.object({
  vendorId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid vendor ID"),
  amount: z.number().min(0),
  currency: z.string().regex(/^[A-Z]{3}$/, "Must be a valid ISO 4217 code"),
  status: z
    .enum(["pending", "processed", "failed", "cancelled"])
    .default("pending"),
  razorpay: z.object({
    transferId: z.string().optional(),
    status: z.enum(["created", "processed", "failed", "reversed"]),
    initiatedAt: z.date().optional(),
    settledAt: z.date().optional(),
    settlementId: z.string().optional(),
    fees: z.object({
      amount: z.number().min(0),
      breakdown: z.array(
        z.object({
          type: z.enum(["transaction", "gst", "other"]),
          amount: z.number().min(0),
        })
      ),
    }),
    utr: z.string().optional(),
  }),
  bankDetails: z.object({
    accountNumber: z.string(),
    ifscCode: z.string(),
    beneficiaryName: z.string(),
    accountType: z.enum(["savings", "current"]),
    bankName: z.string(),
  }),
});

export const NotificationZodSchema = z.object({
  recipientId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid recipient ID"),
  recipientType: z.enum(["customer", "vendor", "admin"]),
  type: z.enum([
    "order_update",
    "payment_reminder",
    "delivery_reminder",
    "daily_summary",
    "promotion",
    "payout_update",
    "vendor_verification",
    "subscription_update",
  ]),
  message: z.object({
    title: z.string(),
    body: z.string(),
    data: z.record(z.any()).optional(),
    translations: z.record(z.string()).optional(),
  }),
  channel: z.array(z.enum(["push", "email", "sms", "in_app"])),
  status: z.enum(["sent", "delivered", "read", "failed"]).default("sent"),
  priority: z.enum(["high", "medium", "low"]).default("medium"),
});

export const MessageZodSchema = z.object({
  senderId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid sender ID"),
  receiverId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid receiver ID"),
  message: z.string(),
  type: z.enum(["text", "image", "document"]),
  status: z.enum(["sent", "delivered", "read"]).default("sent"),
  metadata: z
    .object({
      attachmentUrl: z.string().url().optional(),
      mimeType: z.string().optional(),
    })
    .optional(),
});

export const ComplaintZodSchema = z.object({
  customerId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid customer ID"),
  vendorId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid vendor ID"),
  deliveryId: z
    .string()
    .regex(/^[0-9a-fA-F]{24}$/)
    .optional(),
  category: z.enum(["quality", "delivery", "billing", "other"]),
  description: z.string(),
  status: z
    .enum(["open", "in_progress", "resolved", "escalated"])
    .default("open"),
  resolution: z
    .object({
      details: z.string(),
      resolvedBy: z.string().regex(/^[0-9a-fA-F]{24}$/),
      resolvedAt: z.date(),
    })
    .optional(),
  attachments: z.array(z.string().url()).optional(),
});

export const ReviewZodSchema = z.object({
  customerId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid customer ID"),
  vendorId: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid vendor ID"),
  deliveryId: z
    .string()
    .regex(/^[0-9a-fA-F]{24}$/)
    .optional(),
  rating: z.number().min(1).max(5),
  comment: z.string().optional(),
  status: z.enum(["pending", "approved", "rejected"]).default("pending"),
});

export const AdminZodSchema = z.object({
  email: z.string().email("Valid email is required"),
  passwordHash: z.string(),
  role: z.enum(["super_admin", "support", "finance", "operations"]),
  permissions: z.array(z.string()),
  twoFactor: z.object({
    enabled: z.boolean(),
    secret: z.string().optional(),
    lastVerified: z.date().optional(),
  }),
  status: z.enum(["active", "inactive", "suspended"]).default("active"),
  lastLogin: z.date().optional(),
});

export const AuditLogZodSchema = z.object({
  action: z.enum([
    "vendor_approved",
    "vendor_suspended",
    "payout_processed",
    "customer_updated",
    "order_cancelled",
    "complaint_resolved",
    "payment_processed",
    "subscription_updated",
  ]),
  performedBy: z.string().regex(/^[0-9a-fA-F]{24}$/, "Invalid performer ID"),
  targetId: z
    .string()
    .regex(/^[0-9a-fA-F]{24}$/)
    .optional(),
  targetType: z.enum([
    "customer",
    "vendor",
    "delivery",
    "billing",
    "payout",
    "subscription",
  ]),
  details: z.object({
    before: z.record(z.any()).optional(),
    after: z.record(z.any()).optional(),
    ipAddress: z.string().optional(),
    userAgent: z.string().optional(),
    region: z.string().optional(),
  }),
});

export const AnalyticsZodSchema = z.object({
  vendorId: z
    .string()
    .regex(/^[0-9a-fA-F]{24}$/)
    .optional(),
  type: z.enum([
    "sales",
    "customer_retention",
    "delivery_performance",
    "product_popularity",
    "churn_rate",
    "cohort_analysis",
  ]),
  data: z.record(z.any()),
  period: z.object({
    type: z.enum(["daily", "weekly", "monthly", "yearly"]),
    startDate: z.date(),
    endDate: z.date(),
  }),
  generatedAt: z.date(),
});

// Mongoose Schemas
const CustomerSchema = new Schema<Customer & Document>(
  {
    mobileNumber: {
      type: String,
      required: true,
      unique: true,
      match: /^\+[0-9]{10,12}$/,
    },
    name: { type: String, required: true },
    email: { type: String, match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/ },
    address: {
      street: { type: String, required: true },
      city: { type: String, required: true },
      state: { type: String, required: true },
      postalCode: { type: String, required: true },
      coordinates: {
        type: { type: String, enum: ["Point"], required: true },
        coordinates: { type: [Number], required: true },
      },
      formattedAddress: String,
      deliveryInstructions: String,
    },
    vendorIds: [{ type: Schema.Types.ObjectId, ref: "Vendor" }],
    deliveryPreferences: {
      timeSlot: {
        type: String,
        enum: ["morning", "afternoon", "evening"],
        required: true,
      },
      nonDeliveryDays: [{ type: Date }],
      vacationPeriods: [
        {
          startDate: { type: Date, required: true },
          endDate: { type: Date, required: true },
          status: {
            type: String,
            enum: ["active", "completed", "cancelled"],
            required: true,
          },
        },
      ],
      preferredProducts: [
        {
          productId: {
            type: Schema.Types.ObjectId,
            ref: "Product",
            required: true,
          },
          quantity: { type: Number, min: 1, required: true },
          frequency: {
            type: String,
            enum: ["daily", "weekly", "biweekly", "monthly"],
            required: true,
          },
          subscriptionId: String,
        },
      ],
    },
    language: { type: String, required: true, match: /^[a-z]{2}$/ },
    status: {
      type: String,
      enum: ["active", "inactive", "suspended"],
      default: "active",
    },
    schemaVersion: { type: Number, required: true, default: 1 },
    lastLogin: Date,
    metadata: {
      source: {
        type: String,
        enum: ["qr_scan", "web", "app", "admin"],
        required: true,
      },
      verificationStatus: {
        type: String,
        enum: ["pending", "verified", "failed"],
        default: "pending",
      },
      verificationToken: String,
      deviceInfo: {
        deviceId: String,
        deviceType: { type: String, enum: ["ios", "android", "web"] },
        lastUsed: Date,
      },
      i18n: {
        timezone: { type: String, required: true },
        currency: { type: String, required: true, match: /^[A-Z]{3}$/ },
      },
    },
  },
  {
    timestamps: true,
  }
);
//CustomerSchema.index({ mobileNumber: 1 }, { unique: true });
//CustomerSchema.index({ "address.coordinates": "2dsphere" });
//CustomerSchema.index({ vendorIds: 1 });

const VendorSchema = new Schema<Vendor & Document>(
  {
    mobileNumber: {
      type: String,
      required: true,
      unique: true,
      match: /^\+[0-9]{10,12}$/,
    },
    name: { type: String, required: true },
    email: {
      type: String,
      required: true,
      match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    },
    shop: {
      name: { type: String, required: true },
      location: {
        street: { type: String, required: true },
        city: { type: String, required: true },
        state: { type: String, required: true },
        postalCode: { type: String, required: true },
        coordinates: {
          type: { type: String, enum: ["Point"], required: true },
          coordinates: { type: [Number], required: true },
        },
        deliveryRadiusKm: { type: Number, required: true, min: 0 },
      },
      contact: { type: String, required: true },
      logo: String,
      licenseNumber: String,
      taxId: String,
      businessHours: [
        {
          day: { type: String, required: true },
          open: { type: String, required: true },
          close: { type: String, required: true },
        },
      ],
    },
    uniqueId: { type: String, required: true, unique: true },
    qrCode: {
      url: { type: String, required: true },
      generatedAt: { type: Date, required: true },
      expiresAt: Date,
    },
    deliverySlots: [
      {
        slot: {
          type: String,
          enum: ["morning", "afternoon", "evening"],
          required: true,
        },
        cutoffTime: { type: String, required: true },
        capacity: { type: Number, required: true, min: 0 },
      },
    ],
    status: {
      type: String,
      enum: ["pending", "approved", "suspended", "inactive"],
      default: "pending",
    },
    verification: {
      status: {
        type: String,
        enum: ["pending", "verified", "rejected"],
        default: "pending",
      },
      documents: [
        {
          type: {
            type: String,
            enum: ["license", "tax", "identity"],
            required: true,
          },
          url: { type: String, required: true },
          uploadedAt: { type: Date, required: true },
          verifiedAt: Date,
        },
      ],
    },
    schemaVersion: { type: Number, required: true, default: 1 },
    metadata: {
      onboardingSource: {
        type: String,
        enum: ["self", "admin", "referral"],
        required: true,
      },
      rating: {
        average: { type: Number, min: 0, max: 5, default: 0 },
        count: { type: Number, min: 0, default: 0 },
      },
      apiRateLimit: {
        limit: { type: Number, min: 0, required: true },
        remaining: { type: Number, min: 0, required: true },
        resetAt: { type: Date, required: true },
      },
    },
  },
  {
    timestamps: true,
  }
);
// Add indexes after schema definition
//VendorSchema.index({ mobileNumber: 1 }, { unique: true });
//VendorSchema.index({ uniqueId: 1 }, { unique: true });
//VendorSchema.index({ "shop.location.coordinates": "2dsphere" });

const ProductSchema = new Schema<Product & Document>(
  {
    vendorId: { type: Schema.Types.ObjectId, ref: "Vendor", required: true },
    name: { type: String, required: true },
    category: {
      type: String,
      enum: ["milk", "dairy", "groceries", "essentials"],
      required: true,
    },
    variant: String,
    sku: { type: String, required: true, unique: true },
    price: {
      base: { type: Number, required: true, min: 0 },
      currency: { type: String, required: true, match: /^[A-Z]{3}$/ },
      taxes: [
        {
          type: { type: String, required: true },
          rate: { type: Number, required: true, min: 0 },
          amount: { type: Number, required: true, min: 0 },
        },
      ],
    },
    unit: { type: String, required: true },
    description: String,
    stock: {
      quantity: { type: Number, required: true, min: 0 },
      lowStockThreshold: { type: Number, required: true, min: 0 },
      restockDate: Date,
    },
    available: { type: Boolean, default: true },
    bulkDiscounts: [
      {
        minQuantity: { type: Number, min: 1, required: true },
        price: { type: Number, min: 0, required: true },
        validUntil: Date,
      },
    ],
    promotions: [
      {
        discountType: {
          type: String,
          enum: ["percentage", "fixed"],
          required: true,
        },
        discountValue: { type: Number, min: 0, required: true },
        startDate: { type: Date, required: true },
        endDate: { type: Date, required: true },
        maxUses: { type: Number, min: 0 },
        usedCount: { type: Number, min: 0, default: 0 },
        code: String,
      },
    ],
    images: [String],
    schemaVersion: { type: Number, required: true, default: 1 },
  },
  {
    timestamps: true,
  }
);
// Add indexes after schema definition
//ProductSchema.index({ vendorId: 1 });
//ProductSchema.index({ sku: 1 }, { unique: true });

const DeliverySchema = new Schema<Delivery & Document>(
  {
    customerId: {
      type: Schema.Types.ObjectId,
      ref: "Customer",
      required: true,
    },
    vendorId: { type: Schema.Types.ObjectId, ref: "Vendor", required: true },
    productIds: [
      {
        productId: {
          type: Schema.Types.ObjectId,
          ref: "Product",
          required: true,
        },
        quantity: { type: Number, min: 1, required: true },
        price: { type: Number, min: 0, required: true },
      },
    ],
    totalAmount: { type: Number, min: 0, required: true },
    deliveryDate: { type: Date, required: true },
    timeSlot: {
      type: String,
      enum: ["morning", "afternoon", "evening"],
      required: true,
    },
    status: {
      type: String,
      enum: [
        "pending",
        "processing",
        "shipped",
        "delivered",
        "cancelled",
        "skipped",
      ],
      default: "pending",
    },
    deliveryProof: {
      signature: String,
      photo: String,
      timestamp: Date,
    },
    schemaVersion: { type: Number, required: true, default: 1 },
    metadata: {
      orderSource: {
        type: String,
        enum: ["app", "web", "recurring"],
        required: true,
      },
      deliveryNotes: String,
      subscriptionId: String,
    },
  },
  {
    timestamps: true,
  }
);
// Add indexes after schema definition
//DeliverySchema.index({ customerId: 1 });
//DeliverySchema.index({ vendorId: 1 });
//DeliverySchema.index({ deliveryDate: 1 });

const BillingSchema = new Schema<Billing & Document>(
  {
    customerId: {
      type: Schema.Types.ObjectId,
      ref: "Customer",
      required: true,
    },
    vendorId: { type: Schema.Types.ObjectId, ref: "Vendor", required: true },
    deliveryIds: [{ type: Schema.Types.ObjectId, ref: "Delivery" }],
    totalAmount: { type: Number, min: 0, required: true },
    billingPeriod: {
      type: {
        type: String,
        enum: ["daily", "weekly", "monthly"],
        required: true,
      },
      startDate: { type: Date, required: true },
      endDate: { type: Date, required: true },
    },
    status: {
      type: String,
      enum: ["pending", "paid", "overdue", "failed", "refunded", "disputed"],
      default: "pending",
    },
    paymentDetails: {
      method: {
        type: String,
        enum: ["UPI", "card", "net_banking", "wallet", "subscription"],
        required: true,
      },
      razorpay: {
        orderId: { type: String, required: true },
        paymentId: String,
        signature: String,
        subscriptionId: String,
        status: {
          type: String,
          enum: ["created", "authorized", "captured", "failed", "refunded"],
          required: true,
        },
        amount: { type: Number, min: 0, required: true },
        currency: { type: String, match: /^[A-Z]{3}$/, required: true },
        receipt: { type: String, required: true },
        createdAt: { type: Date, required: true },
        capturedAt: Date,
        refundedAt: Date,
        refundDetails: {
          refundId: String,
          amount: { type: Number, min: 0 },
          status: { type: String, enum: ["processed", "pending", "failed"] },
          reason: String,
        },
        webhookStatus: {
          lastReceived: Date,
          events: [
            {
              event: String,
              payload: Schema.Types.Mixed,
              receivedAt: Date,
            },
          ],
        },
      },
      attempts: [
        {
          timestamp: { type: Date, required: true },
          status: { type: String, enum: ["success", "failed"], required: true },
          errorCode: String,
          errorDescription: String,
        },
      ],
    },
    invoice: {
      number: { type: String, required: true },
      pdfUrl: String,
      generatedAt: { type: Date, required: true },
    },
    schemaVersion: { type: Number, required: true, default: 1 },
  },
  {
    timestamps: true,
  }
);
// Add indexes after schema definition
//BillingSchema.index({ customerId: 1 });
//BillingSchema.index({ vendorId: 1 });
//BillingSchema.index({ "paymentDetails.razorpay.orderId": 1 });
//BillingSchema.index({ "invoice.number": 1 }, { unique: true });

const VendorPayoutSchema = new Schema<VendorPayout & Document>(
  {
    vendorId: { type: Schema.Types.ObjectId, ref: "Vendor", required: true },
    amount: { type: Number, min: 0, required: true },
    currency: { type: String, match: /^[A-Z]{3}$/, required: true },
    status: {
      type: String,
      enum: ["pending", "processed", "failed", "cancelled"],
      default: "pending",
    },
    razorpay: {
      transferId: String,
      status: {
        type: String,
        enum: ["created", "processed", "failed", "reversed"],
        required: true,
      },
      initiatedAt: Date,
      settledAt: Date,
      settlementId: String,
      fees: {
        amount: { type: Number, min: 0, required: true },
        breakdown: [
          {
            type: {
              type: String,
              enum: ["transaction", "gst", "other"],
              required: true,
            },
            amount: { type: Number, min: 0, required: true },
          },
        ],
      },
      utr: String,
    },
    bankDetails: {
      accountNumber: { type: String, required: true },
      ifscCode: { type: String, required: true },
      beneficiaryName: { type: String, required: true },
      accountType: {
        type: String,
        enum: ["savings", "current"],
        required: true,
      },
      bankName: { type: String, required: true },
    },
    schemaVersion: { type: Number, required: true, default: 1 },
  },
  {
    timestamps: true,
  }
);
// Add indexes after schema definition
//VendorPayoutSchema.index({ vendorId: 1 });
//VendorPayoutSchema.index({ "razorpay.transferId": 1 });

const NotificationSchema = new Schema<Notification & Document>(
  {
    recipientId: { type: Schema.Types.ObjectId, required: true },
    recipientType: {
      type: String,
      enum: ["customer", "vendor", "admin"],
      required: true,
    },
    type: {
      type: String,
      enum: [
        "order_update",
        "payment_reminder",
        "delivery_reminder",
        "daily_summary",
        "promotion",
        "payout_update",
        "vendor_verification",
        "subscription_update",
      ],
      required: true,
    },
    message: {
      title: { type: String, required: true },
      body: { type: String, required: true },
      data: Schema.Types.Mixed,
      translations: Schema.Types.Mixed,
    },
    channel: [
      {
        type: String,
        enum: ["push", "email", "sms", "in_app"],
        required: true,
      },
    ],
    status: {
      type: String,
      enum: ["sent", "delivered", "read", "failed"],
      default: "sent",
    },
    priority: {
      type: String,
      enum: ["high", "medium", "low"],
      default: "medium",
    },
    schemaVersion: { type: Number, required: true, default: 1 },
  },
  {
    timestamps: true,
  }
);
// Add indexes after schema definition
//NotificationSchema.index({ recipientId: 1 });
//NotificationSchema.index({ recipientType: 1 });

const MessageSchema = new Schema<Message & Document>(
  {
    senderId: { type: Schema.Types.ObjectId, required: true },
    receiverId: { type: Schema.Types.ObjectId, required: true },
    message: { type: String, required: true },
    type: { type: String, enum: ["text", "image", "document"], required: true },
    status: {
      type: String,
      enum: ["sent", "delivered", "read"],
      default: "sent",
    },
    schemaVersion: { type: Number, required: true, default: 1 },
    metadata: {
      attachmentUrl: String,
      mimeType: String,
    },
  },
  {
    timestamps: true,
  }
);
//MessageSchema.index({ senderId: 1 });
//MessageSchema.index({ receiverId: 1 });

const ComplaintSchema = new Schema<Complaint & Document>(
  {
    customerId: {
      type: Schema.Types.ObjectId,
      ref: "Customer",
      required: true,
    },
    vendorId: { type: Schema.Types.ObjectId, ref: "Vendor", required: true },
    deliveryId: { type: Schema.Types.ObjectId, ref: "Delivery" },
    category: {
      type: String,
      enum: ["quality", "delivery", "billing", "other"],
      required: true,
    },
    description: { type: String, required: true },
    status: {
      type: String,
      enum: ["open", "in_progress", "resolved", "escalated"],
      default: "open",
    },
    resolution: {
      details: String,
      resolvedBy: { type: Schema.Types.ObjectId, ref: "Admin" },
      resolvedAt: Date,
    },
    attachments: [String],
    schemaVersion: { type: Number, required: true, default: 1 },
  },
  {
    timestamps: true,
  }
);
// Add indexes after schema definition
//ComplaintSchema.index({ customerId: 1 });
//ComplaintSchema.index({ vendorId: 1 });
//ComplaintSchema.index({ deliveryId: 1 });

const ReviewSchema = new Schema<Review & Document>(
  {
    customerId: {
      type: Schema.Types.ObjectId,
      ref: "Customer",
      required: true,
    },
    vendorId: { type: Schema.Types.ObjectId, ref: "Vendor", required: true },
    deliveryId: { type: Schema.Types.ObjectId, ref: "Delivery" },
    rating: { type: Number, min: 1, max: 5, required: true },
    comment: String,
    status: {
      type: String,
      enum: ["pending", "approved", "rejected"],
      default: "pending",
    },
    schemaVersion: { type: Number, required: true, default: 1 },
  },
  {
    timestamps: true,
  }
);
//ReviewSchema.index({ customerId: 1 });
//ReviewSchema.index({ vendorId: 1 });

const AdminSchema = new Schema<Admin & Document>(
  {
    email: {
      type: String,
      required: true,
      unique: true,
      match: /^[^\s@]+@[^\s@]+\.[^\s@]+$/,
    },
    passwordHash: { type: String, required: true },
    role: {
      type: String,
      enum: ["super_admin", "support", "finance", "operations"],
      required: true,
    },
    permissions: [{ type: String, required: true }],
    twoFactor: {
      enabled: { type: Boolean, required: true },
      secret: String,
      lastVerified: Date,
    },
    status: {
      type: String,
      enum: ["active", "inactive", "suspended"],
      default: "active",
    },
    schemaVersion: { type: Number, required: true, default: 1 },
    lastLogin: Date,
  },
  {
    timestamps: true,
  }
);
//AdminSchema.index({ email: 1 }, { unique: true });

const AuditLogSchema = new Schema<AuditLog & Document>(
  {
    action: {
      type: String,
      enum: [
        "vendor_approved",
        "vendor_suspended",
        "payout_processed",
        "customer_updated",
        "order_cancelled",
        "complaint_resolved",
        "payment_processed",
        "subscription_updated",
      ],
      required: true,
    },
    performedBy: { type: Schema.Types.ObjectId, required: true },
    targetId: { type: Schema.Types.ObjectId },
    targetType: {
      type: String,
      enum: [
        "customer",
        "vendor",
        "delivery",
        "billing",
        "payout",
        "subscription",
      ],
      required: true,
    },
    details: {
      before: Schema.Types.Mixed,
      after: Schema.Types.Mixed,
      ipAddress: String,
      userAgent: String,
      region: String,
    },
    schemaVersion: { type: Number, required: true, default: 1 },
  },
  {
    timestamps: true,
  }
);
// Add indexes after schema definition
//AuditLogSchema.index({ performedBy: 1 });
//AuditLogSchema.index({ targetId: 1 });
//AuditLogSchema.index({ targetType: 1 });

const AnalyticsSchema = new Schema<Analytics & Document>(
  {
    vendorId: { type: Schema.Types.ObjectId, ref: "Vendor" },
    type: {
      type: String,
      enum: [
        "sales",
        "customer_retention",
        "delivery_performance",
        "product_popularity",
        "churn_rate",
        "cohort_analysis",
      ],
      required: true,
    },
    data: Schema.Types.Mixed,
    period: {
      type: {
        type: String,
        enum: ["daily", "weekly", "monthly", "yearly"],
        required: true,
      },
      startDate: { type: Date, required: true },
      endDate: { type: Date, required: true },
    },
    schemaVersion: { type: Number, required: true, default: 1 },
    generatedAt: { type: Date, required: true },
  },
  {
    timestamps: true,
  }
);
// Add indexes after schema definition
//AnalyticsSchema.index({ vendorId: 1 });
//AnalyticsSchema.index({ type: 1 });
//AnalyticsSchema.index({ "period.startDate": 1 });

// Models
export const CustomerModel = model<Customer & Document>(
  "Customer",
  CustomerSchema
);
export const VendorModel = model<Vendor & Document>("Vendor", VendorSchema);
export const ProductModel = model<Product & Document>("Product", ProductSchema);
export const DeliveryModel = model<Delivery & Document>(
  "Delivery",
  DeliverySchema
);
export const BillingModel = model<Billing & Document>("Billing", BillingSchema);
export const VendorPayoutModel = model<VendorPayout & Document>(
  "VendorPayout",
  VendorPayoutSchema
);
export const NotificationModel = model<Notification & Document>(
  "Notification",
  NotificationSchema
);
export const MessageModel = model<Message & Document>("Message", MessageSchema);
export const ComplaintModel = model<Complaint & Document>(
  "Complaint",
  ComplaintSchema
);
export const ReviewModel = model<Review & Document>("Review", ReviewSchema);
export const AdminModel = model<Admin & Document>("Admin", AdminSchema);
export const AuditLogModel = model<AuditLog & Document>(
  "AuditLog",
  AuditLogSchema
);
export const AnalyticsModel = model<Analytics & Document>(
  "Analytics",
  AnalyticsSchema
);

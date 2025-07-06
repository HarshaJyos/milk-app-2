import { ObjectId } from "mongodb";

export interface GeoJSON {
  type: "Point";
  coordinates: [number, number]; // [longitude, latitude]
}

export interface Customer {
  _id: ObjectId;
  mobileNumber: string; // Unique, E.164 format
  name: string;
  email?: string; // Validated email format
  address: {
    street: string;
    city: string;
    state: string;
    postalCode: string;
    coordinates: GeoJSON;
    formattedAddress?: string;
    deliveryInstructions?: string;
  };
  vendorIds: ObjectId[]; // Support multiple vendors
  deliveryPreferences: {
    timeSlot: "morning" | "afternoon" | "evening";
    nonDeliveryDays: Date[];
    vacationPeriods: Array<{
      startDate: Date;
      endDate: Date;
      status: "active" | "completed" | "cancelled";
    }>;
    preferredProducts: Array<{
      productId: ObjectId;
      quantity: number;
      frequency: "daily" | "weekly" | "biweekly" | "monthly";
      subscriptionId?: string; // Razorpay subscription ID
    }>;
  };
  language: string; // ISO 639-1 code
  status: "active" | "inactive" | "suspended";
  schemaVersion: number;
  createdAt: Date;
  updatedAt: Date;
  lastLogin?: Date;
  metadata: {
    source: "qr_scan" | "web" | "app" | "admin";
    verificationStatus: "pending" | "verified" | "failed";
    verificationToken: string; // Made required to match usage
    deviceInfo?: {
      deviceId: string;
      deviceType: "ios" | "android" | "web";
      lastUsed: Date;
    };
    i18n: {
      timezone: string; // e.g., Asia/Kolkata
      currency: string; // ISO 4217 code
    };
  };
}

export interface Vendor {
  _id: ObjectId;
  mobileNumber: string; // Unique, E.164 format
  name: string;
  email: string;
  shop: {
    name: string;
    location: {
      street: string;
      city: string;
      state: string;
      postalCode: string;
      coordinates: GeoJSON;
      deliveryRadiusKm: number;
    };
    contact: string;
    logo?: string; // Azure Blob Storage URL
    licenseNumber?: string; // Encrypted
    taxId?: string; // Encrypted
    businessHours: Array<{
      day: string;
      open: string; // ISO 8601 time
      close: string; // ISO 8601 time
    }>;
  };
  uniqueId: string; // Indexed, unique
  qrCode: {
    url: string; // Azure Blob Storage URL
    generatedAt: Date;
    expiresAt?: Date;
  };
  deliverySlots: Array<{
    slot: "morning" | "afternoon" | "evening";
    cutoffTime: string; // ISO 8601 time
    capacity: number;
  }>;
  status: "pending" | "approved" | "suspended" | "inactive";
  verification: {
    status: "pending" | "verified" | "rejected";
    documents: Array<{
      type: "license" | "tax" | "identity";
      url: string; // Azure Blob Storage URL
      uploadedAt: Date;
      verifiedAt?: Date;
    }>;
  };
  schemaVersion: number;
  createdAt: Date;
  updatedAt: Date;
  metadata: {
    onboardingSource: "self" | "admin" | "referral";
    rating: {
      average: number;
      count: number;
    };
    apiRateLimit: {
      limit: number;
      remaining: number;
      resetAt: Date;
    };
    verificationToken: string; // Made required to match usage
  };
}

export interface Product {
  _id: ObjectId;
  vendorId: ObjectId;
  name: string;
  category: "milk" | "dairy" | "groceries" | "essentials";
  variant?: string;
  sku: string; // Unique Stock Keeping Unit
  price: {
    base: number;
    currency: string; // ISO 4217 code
    taxes: Array<{
      type: string;
      rate: number;
      amount: number;
    }>;
  };
  unit: string;
  description?: string;
  stock: {
    quantity: number;
    lowStockThreshold: number;
    restockDate?: Date;
  };
  available: boolean;
  bulkDiscounts?: Array<{
    minQuantity: number;
    price: number;
    validUntil?: Date;
  }>;
  promotions?: Array<{
    discountType: "percentage" | "fixed";
    discountValue: number;
    startDate: Date;
    endDate: Date;
    maxUses?: number;
    usedCount: number;
    code?: string; // Promo code
  }>;
  images?: string[]; // Azure Blob Storage URLs
  schemaVersion: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface Delivery {
  _id: ObjectId;
  customerId: ObjectId;
  vendorId: ObjectId;
  productIds: Array<{
    productId: ObjectId;
    quantity: number;
    price: number;
  }>;
  totalAmount: number;
  deliveryDate: Date;
  timeSlot: "morning" | "afternoon" | "evening";
  status:
    | "pending"
    | "processing"
    | "shipped"
    | "delivered"
    | "cancelled"
    | "skipped";
  deliveryProof?: {
    signature?: string; // Azure Blob Storage URL
    photo?: string; // Azure Blob Storage URL
    timestamp: Date;
  };
  schemaVersion: number;
  createdAt: Date;
  updatedAt: Date;
  metadata: {
    orderSource: "app" | "web" | "recurring";
    deliveryNotes?: string;
    subscriptionId?: string; // Razorpay subscription ID
  };
}

export interface Billing {
  _id: ObjectId;
  customerId: ObjectId;
  vendorId: ObjectId;
  deliveryIds: ObjectId[];
  totalAmount: number;
  billingPeriod: {
    type: "daily" | "weekly" | "monthly";
    startDate: Date;
    endDate: Date;
  };
  status: "pending" | "paid" | "overdue" | "failed" | "refunded" | "disputed";
  paymentDetails: {
    method: "UPI" | "card" | "net_banking" | "wallet" | "subscription";
    razorpay: {
      orderId: string;
      paymentId?: string;
      signature?: string;
      subscriptionId?: string;
      status: "created" | "authorized" | "captured" | "failed" | "refunded";
      amount: number;
      currency: string;
      receipt: string;
      createdAt: Date;
      capturedAt?: Date;
      refundedAt?: Date;
      refundDetails?: {
        refundId: string;
        amount: number;
        status: "processed" | "pending" | "failed";
        reason?: string;
      };
      webhookStatus: {
        lastReceived: Date;
        events: Array<{
          event: string;
          payload: Record<string, any>;
          receivedAt: Date;
        }>;
      };
    };
    attempts: Array<{
      timestamp: Date;
      status: "success" | "failed";
      errorCode?: string;
      errorDescription?: string;
    }>;
  };
  invoice: {
    number: string;
    pdfUrl?: string; // Azure Blob Storage URL
    generatedAt: Date;
  };
  schemaVersion: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface VendorPayout {
  _id: ObjectId;
  vendorId: ObjectId;
  amount: number; // In paise
  currency: string; // ISO 4217 code
  status: "pending" | "processed" | "failed" | "cancelled";
  razorpay: {
    transferId?: string;
    status: "created" | "processed" | "failed" | "reversed";
    initiatedAt?: Date;
    settledAt?: Date;
    settlementId?: string;
    fees: {
      amount: number;
      breakdown: Array<{
        type: "transaction" | "gst" | "other";
        amount: number;
      }>;
    };
    utr?: string;
  };
  bankDetails: {
    accountNumber: string; // Encrypted
    ifscCode: string; // Encrypted
    beneficiaryName: string;
    accountType: "savings" | "current";
    bankName: string;
  };
  schemaVersion: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface Notification {
  _id: ObjectId;
  recipientId: ObjectId;
  recipientType: "customer" | "vendor" | "admin";
  type:
    | "order_update"
    | "payment_reminder"
    | "delivery_reminder"
    | "daily_summary"
    | "promotion"
    | "payout_update"
    | "vendor_verification"
    | "subscription_update";
  message: {
    title: string;
    body: string;
    data?: Record<string, any>;
    translations?: Record<string, string>;
  };
  channel: Array<"push" | "email" | "sms" | "in_app">;
  status: "sent" | "delivered" | "read" | "failed";
  priority: "high" | "medium" | "low";
  schemaVersion: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface Message {
  _id: ObjectId;
  senderId: ObjectId;
  receiverId: ObjectId;
  message: string;
  type: "text" | "image" | "document";
  status: "sent" | "delivered" | "read";
  schemaVersion: number;
  createdAt: Date;
  metadata?: {
    attachmentUrl?: string; // Azure Blob Storage URL
    mimeType?: string;
  };
}

export interface Complaint {
  _id: ObjectId;
  customerId: ObjectId;
  vendorId: ObjectId;
  deliveryId?: ObjectId;
  category: "quality" | "delivery" | "billing" | "other";
  description: string;
  status: "open" | "in_progress" | "resolved" | "escalated";
  resolution?: {
    details: string;
    resolvedBy: ObjectId;
    resolvedAt: Date;
  };
  attachments?: string[]; // Azure Blob Storage URLs
  schemaVersion: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface Review {
  _id: ObjectId;
  customerId: ObjectId;
  vendorId: ObjectId;
  deliveryId?: ObjectId;
  rating: number; // 1 to 5
  comment?: string;
  status: "pending" | "approved" | "rejected";
  schemaVersion: number;
  createdAt: Date;
  updatedAt: Date;
}

export interface Admin {
  _id: ObjectId;
  email: string;
  passwordHash: string; // Encrypted
  role: "super_admin" | "support" | "finance" | "operations";
  permissions: string[];
  twoFactor: {
    enabled: boolean;
    secret?: string; // Encrypted
    lastVerified?: Date;
  };
  status: "active" | "inactive" | "suspended";
  schemaVersion: number;
  createdAt: Date;
  updatedAt: Date;
  lastLogin?: Date;
}

export interface AuditLog {
  _id: ObjectId;
  action:
    | "vendor_approved"
    | "vendor_suspended"
    | "payout_processed"
    | "customer_updated"
    | "order_cancelled"
    | "complaint_resolved"
    | "payment_processed"
    | "subscription_updated";
  performedBy: ObjectId;
  targetId?: ObjectId;
  targetType:
    | "customer"
    | "vendor"
    | "delivery"
    | "billing"
    | "payout"
    | "subscription";
  details: {
    before?: Record<string, any>;
    after?: Record<string, any>;
    ipAddress?: string;
    userAgent?: string;
    region?: string;
  };
  schemaVersion: number;
  createdAt: Date;
}

export interface Analytics {
  _id: ObjectId;
  vendorId?: ObjectId;
  type:
    | "sales"
    | "customer_retention"
    | "delivery_performance"
    | "product_popularity"
    | "churn_rate"
    | "cohort_analysis";
  data: Record<string, any>;
  period: {
    type: "daily" | "weekly" | "monthly" | "yearly";
    startDate: Date;
    endDate: Date;
  };
  schemaVersion: number;
  generatedAt: Date;
}

import express from "express";
import cors from "cors";
import dotenv from "dotenv";
import { MongoClient, ObjectId } from "mongodb";
import Stripe from "stripe";
import { betterAuth } from "better-auth";
import { mongodbAdapter } from "better-auth/adapters/mongodb";
import { toNodeHandler } from "better-auth/node";
import { jwt } from "better-auth/plugins";
import { createRemoteJWKSet, jwtVerify } from "jose";

dotenv.config();



const configuredPort = Number(process.env.PORT || 5000);

if (!Number.isInteger(configuredPort) || configuredPort < 1 || configuredPort > 65535) {
  throw new Error("PORT must be an integer between 1 and 65535.");
}

const PORT = configuredPort;
const DATABASE_NAME = process.env.MONGODB_DATABASE || "equipmentrentaldb";

const stripTrailingSlash = (url) => url.replace(/\/+$/, "");

const AUTH_BASE_URL = stripTrailingSlash(
  process.env.BETTER_AUTH_URL || `http://localhost:${PORT}`
);
const CLIENT_URL = stripTrailingSlash(
  process.env.CLIENT_URL || "http://localhost:3000"
);

for (const key of ["MONGODB_URI", "BETTER_AUTH_SECRET", "STRIPE_SECRET_KEY"]) {
  if (!process.env[key]) {
    throw new Error(`${key} is missing from .env`);
  }
}

const RENTAL_TYPES = ["hourly", "daily", "weekly", "monthly"];
const USER_ROLES = ["customer", "owner", "admin"];

const app = express();
const mongoClient = new MongoClient(process.env.MONGODB_URI);
const stripe = new Stripe(process.env.STRIPE_SECRET_KEY);
const JWKS = createRemoteJWKSet(new URL(`${AUTH_BASE_URL}/api/auth/jwks`));

let db;
let auth;
let httpServer;

// ============================================
// HELPERS
// ============================================

const fail = (res, status, message) =>
  res.status(status).json({ success: false, message });

const serverError = (res, message) => fail(res, 500, message);

const isValidObjectId = (id) =>
  typeof id === "string" && /^[0-9a-fA-F]{24}$/.test(id);

const toObjectId = (id) => new ObjectId(id);

const isValidImageUrl = (value) =>
  typeof value === "string" && /^https?:\/\/\S+$/i.test(value);

// Better Auth may store the user id as a string or as an ObjectId,
// so we check all the possible shapes.
const getUserIdFilter = (id) => {
  const conditions = [{ _id: id }, { id }];

  if (isValidObjectId(id)) {
    conditions.push({ _id: toObjectId(id) });
  }

  return { $or: conditions };
};

const getUserById = (id) => db.collection("user").findOne(getUserIdFilter(id));

const formatUser = (user, fallback) => ({
  id: user._id?.toString() || user.id || fallback.id,
  name: user.name || "",
  email: user.email || fallback.email,
  image: user.image || null,
  emailVerified: user.emailVerified || false,
  role: user.role || "customer",
  createdAt: user.createdAt || null,
});

// Adds the extra fields the frontend expects on booking objects.
const formatBooking = (booking) => ({
  ...booking,
  bookingStatus: booking.status || "pending",
  totalDays: booking.rentalDuration || 0,
  totalAmount: booking.totalPrice || 0,
});

const getPaymentIntentId = (session) =>
  typeof session.payment_intent === "string"
    ? session.payment_intent
    : session.payment_intent?.id || null;

// ============================================
// EQUIPMENT VALIDATION
// ============================================

const EQUIPMENT_TEXT_FIELDS = {
  name: "Equipment name",
  description: "Description",
  category: "Category",
  location: "Location",
};

const MISSING_EQUIPMENT_INFO = "Please provide all required equipment information.";

// Validates equipment input for both create (all fields required)
// and update (partial: only the provided fields are checked).
const parseEquipmentInput = (body, { partial = false } = {}) => {
  const data = {};

  for (const [field, label] of Object.entries(EQUIPMENT_TEXT_FIELDS)) {
    const value = body[field];

    if (value === undefined && partial) continue;

    if (typeof value !== "string" || !value.trim()) {
      return {
        error: partial ? `${label} is required.` : MISSING_EQUIPMENT_INFO,
      };
    }

    data[field] = value.trim();
  }

  if (!partial && (body.price === undefined || body.quantity === undefined)) {
    return { error: MISSING_EQUIPMENT_INFO };
  }

  if (body.price !== undefined) {
    const price = Number(body.price);

    if (!Number.isFinite(price) || price <= 0) {
      return { error: "Price must be greater than zero." };
    }

    data.price = price;
  }

  if (body.quantity !== undefined) {
    const quantity = Number(body.quantity);

    if (!Number.isInteger(quantity) || quantity < 1) {
      return { error: "Quantity must be at least 1." };
    }

    data.quantity = quantity;
  }

  if (!partial || body.rentalType !== undefined) {
    if (!RENTAL_TYPES.includes(body.rentalType)) {
      return { error: "Invalid rental type." };
    }

    data.rentalType = body.rentalType;
  }

  if (body.image !== undefined) {
    if (body.image && !isValidImageUrl(body.image)) {
      return { error: "Please provide a valid image URL." };
    }

    data.image = body.image ? body.image.trim() : "";
  }

  return { data };
};

// ============================================
// RENTAL PRICING
// ============================================

const MS_PER_HOUR = 1000 * 60 * 60;
const MS_PER_DAY = MS_PER_HOUR * 24;

const calculateRentalDuration = (rentalType, start, end) => {
  const diff = end.getTime() - start.getTime();
  const days = Math.ceil(diff / MS_PER_DAY);

  switch (rentalType) {
    case "hourly":
      return Math.ceil(diff / MS_PER_HOUR);
    case "weekly":
      return Math.ceil(days / 7);
    case "monthly":
      return Math.ceil(days / 30);
    default:
      return days;
  }
};

// ============================================
// PAYMENT COMPLETION
// ============================================

// Called from both the Stripe webhook and the verify-session route.
// Everything here is idempotent, so repeated calls are safe.
const handleSuccessfulCheckout = async (session) => {
  if (session.payment_status !== "paid") {
    console.log("Checkout session is not paid:", session.id);
    return null;
  }

  const pendingPayment = await db
    .collection("pendingPayments")
    .findOne({ sessionId: session.id });

  if (!pendingPayment) {
    throw new Error(`Pending payment not found: ${session.id}`);
  }

  const isVerified =
    session.amount_total === Math.round(pendingPayment.totalPrice * 100) &&
    session.currency === pendingPayment.currency &&
    session.metadata?.customerId === pendingPayment.customerId;

  if (!isVerified) {
    throw new Error(`Payment verification failed: ${session.id}`);
  }

  const paidAt = session.created ? new Date(session.created * 1000) : new Date();
  const paymentIntentId = getPaymentIntentId(session);

  let booking = await db
    .collection("bookings")
    .findOne({ stripeSessionId: session.id });

  if (!booking) {
    const newBooking = {
      equipmentId: pendingPayment.equipmentId,
      equipmentName: pendingPayment.equipmentName,
      equipmentImage: pendingPayment.equipmentImage,
      category: pendingPayment.category,

      ownerId: pendingPayment.ownerId,
      ownerName: pendingPayment.ownerName,
      ownerEmail: pendingPayment.ownerEmail,

      customerId: pendingPayment.customerId,
      customerName: pendingPayment.customerName,
      customerEmail: pendingPayment.customerEmail,

      startDate: pendingPayment.startDate,
      endDate: pendingPayment.endDate,

      rentalType: pendingPayment.rentalType,
      pricePerUnit: pendingPayment.pricePerUnit,
      rentalDuration: pendingPayment.rentalDuration,
      quantity: pendingPayment.quantity,
      totalPrice: pendingPayment.totalPrice,

      contactPhone: pendingPayment.contactPhone,
      address: pendingPayment.address,
      notes: pendingPayment.notes,

      status: "pending",
      paymentStatus: "paid",

      stripeSessionId: session.id,
      paymentIntentId,

      currency: session.currency,
      paidAt,
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    try {
      const { insertedId } = await db.collection("bookings").insertOne(newBooking);
      booking = { _id: insertedId, ...newBooking };
    } catch (error) {
      // 11000 = duplicate key: the webhook and verify-session raced each other.
      if (error.code !== 11000) throw error;

      booking = await db
        .collection("bookings")
        .findOne({ stripeSessionId: session.id });

      if (!booking) throw error;
    }
  }

  await db.collection("transactions").updateOne(
    { stripeSessionId: session.id },
    {
      $setOnInsert: {
        stripeSessionId: session.id,
        paymentIntentId,
        bookingId: booking._id.toString(),

        customerId: pendingPayment.customerId,
        customerName: pendingPayment.customerName,
        customerEmail: pendingPayment.customerEmail,

        ownerId: pendingPayment.ownerId,
        equipmentId: pendingPayment.equipmentId,
        equipmentName: pendingPayment.equipmentName,

        amount: pendingPayment.totalPrice,
        currency: session.currency,
        paymentStatus: "paid",
        paymentMethod: "stripe",

        paidAt,
        createdAt: new Date(),
      },
    },
    { upsert: true }
  );

  await db.collection("pendingPayments").updateOne(
    { sessionId: session.id },
    {
      $set: {
        paymentStatus: "paid",
        bookingId: booking._id.toString(),
        paymentIntentId,
        paidAt,
        updatedAt: new Date(),
      },
    }
  );

  console.log("Payment completed successfully:", session.id);

  return booking;
};

// ============================================
// MIDDLEWARE
// ============================================

app.use(
  cors({
    origin: CLIENT_URL,
    credentials: true,
    allowedHeaders: ["Content-Type", "Authorization"],
    methods: ["GET", "POST", "PATCH", "PUT", "DELETE", "OPTIONS"],
  })
);

// Stripe needs the raw request body to verify the signature,
// so this route must stay above express.json().
app.post(
  "/api/payments/webhook",
  express.raw({ type: "application/json" }),
  async (req, res) => {
    const webhookSecret = process.env.STRIPE_WEBHOOK_SECRET;

    if (!webhookSecret) {
      return fail(res, 503, "Stripe webhook secret is not configured.");
    }

    let event;

    try {
      event = stripe.webhooks.constructEvent(
        req.body,
        req.headers["stripe-signature"],
        webhookSecret
      );
    } catch (error) {
      console.error("Stripe webhook signature error:", error.message);
      return fail(res, 400, "Invalid Stripe webhook signature.");
    }

    try {
      if (event.type === "checkout.session.completed") {
        await handleSuccessfulCheckout(event.data.object);
      }

      return res.status(200).json({ received: true });
    } catch (error) {
      console.error("Stripe webhook processing error:", error);
      return fail(res, 500, "Webhook processing failed.");
    }
  }
);

app.use(express.json());

// ============================================
// DATABASE & BETTER AUTH
// ============================================

const connectDB = async () => {
  await mongoClient.connect();
  db = mongoClient.db(DATABASE_NAME);
  console.log("MongoDB Connected Successfully!");

  const googleEnabled =
    process.env.GOOGLE_CLIENT_ID && process.env.GOOGLE_CLIENT_SECRET;

  auth = betterAuth({
    database: mongodbAdapter(db),
    secret: process.env.BETTER_AUTH_SECRET,
    baseURL: AUTH_BASE_URL,
    basePath: "/api/auth",
    trustedOrigins: [CLIENT_URL],

    emailAndPassword: {
      enabled: true,
      minPasswordLength: 6,
    },

    user: {
      additionalFields: {
        role: {
          type: "string",
          required: false,
          defaultValue: "customer",
          input: true,
        },
      },
    },

    databaseHooks: {
      user: {
        create: {
          // Users can only sign up as customer or owner, never admin.
          before: async (user) => ({
            data: {
              ...user,
              role: user.role === "owner" ? "owner" : "customer",
            },
          }),
        },
      },
    },

    socialProviders: googleEnabled
      ? {
          google: {
            clientId: process.env.GOOGLE_CLIENT_ID,
            clientSecret: process.env.GOOGLE_CLIENT_SECRET,
          },
        }
      : {},

    plugins: [
      jwt({
        jwt: {
          definePayload: ({ user }) => ({
            id: user.id,
            name: user.name,
            email: user.email,
            image: user.image || null,
            role: user.role || "customer",
            emailVerified: user.emailVerified,
            createdAt: user.createdAt
              ? new Date(user.createdAt).toISOString()
              : null,
          }),
          issuer: AUTH_BASE_URL,
          audience: AUTH_BASE_URL,
          expirationTime: "15m",
        },
      }),
    ],
  });

  console.log("Better Auth Configured Successfully!");
  console.log("JWT Authentication Configured Successfully!");
};

// ============================================
// AUTH MIDDLEWARE
// ============================================

const verifyToken = async (req, res, next) => {
  try {
    const authHeader = req.headers.authorization;

    if (!authHeader?.startsWith("Bearer ")) {
      return fail(
        res,
        401,
        "Authorization token is required. Please login first."
      );
    }

    const token = authHeader.slice(7).trim();

    if (!token) {
      return fail(res, 401, "Invalid authorization token.");
    }

    const { payload } = await jwtVerify(token, JWKS, {
      issuer: AUTH_BASE_URL,
      audience: AUTH_BASE_URL,
    });

    const userId = payload.sub || payload.id;

    if (!userId || !payload.email) {
      return fail(res, 401, "Invalid JWT payload.");
    }

    req.user = {
      id: String(userId),
      name: payload.name || "",
      email: payload.email,
      image: payload.image || null,
      role: payload.role || "customer",
      emailVerified: payload.emailVerified,
      createdAt: payload.createdAt || null,
    };

    return next();
  } catch (error) {
    console.error("JWT verification error:", error.message);
    return fail(res, 401, "Invalid or expired JWT token.");
  }
};

const allowRole = (role) => (req, res, next) => {
  if (req.user.role !== role) {
    return fail(res, 403, `${role} access only.`);
  }

  return next();
};

const verifyCustomer = allowRole("customer");
const verifyOwner = allowRole("owner");
const verifyAdmin = allowRole("admin");

// ============================================
// BASIC ROUTES & BETTER AUTH
// ============================================

app.get("/", (req, res) => {
  res.status(200).json({
    success: true,
    message: "Equipora Server is running!",
  });
});

app.get("/health", async (req, res) => {
  try {
    await db.command({ ping: 1 });
    return res.status(200).json({ success: true, status: "ok" });
  } catch (error) {
    console.error("Health check failed:", error.message);
    return res.status(503).json({ success: false, status: "unavailable" });
  }
});

app.all("/api/auth/{*any}", (req, res) => toNodeHandler(auth)(req, res));

// ============================================
// USER PROFILE
// ============================================

app.get("/api/users/me", verifyToken, async (req, res) => {
  try {
    const user = await getUserById(req.user.id);

    if (!user) {
      return fail(res, 404, "User not found in database.");
    }

    return res.status(200).json({
      success: true,
      data: formatUser(user, req.user),
    });
  } catch (error) {
    console.error("Get profile error:", error);
    return serverError(res, "Failed to get profile.");
  }
});

app.patch("/api/users/profile", verifyToken, async (req, res) => {
  try {
    const { name, image } = req.body;
    const updateData = {};

    if (name !== undefined) {
      if (
        typeof name !== "string" ||
        name.trim().length < 2 ||
        name.trim().length > 80
      ) {
        return fail(res, 400, "Name must contain 2 to 80 characters.");
      }

      updateData.name = name.trim();
    }

    if (image !== undefined) {
      if (image && !isValidImageUrl(image)) {
        return fail(res, 400, "Please provide a valid image URL.");
      }

      updateData.image = image || null;
    }

    if (Object.keys(updateData).length === 0) {
      return fail(res, 400, "No profile information provided.");
    }

    const userFilter = getUserIdFilter(req.user.id);

    const result = await db.collection("user").updateOne(userFilter, {
      $set: { ...updateData, updatedAt: new Date() },
    });

    if (!result.matchedCount) {
      return fail(res, 404, "User not found in database.");
    }

    const updatedUser = await db.collection("user").findOne(userFilter);

    return res.status(200).json({
      success: true,
      message: "Profile updated successfully.",
      data: formatUser(updatedUser, req.user),
    });
  } catch (error) {
    console.error("Update profile error:", error);
    return serverError(res, "Failed to update profile.");
  }
});

// ============================================
// EQUIPMENT
// ============================================

// Public list of approved equipment with search, filters and sorting
app.get("/api/equipments", async (req, res) => {
  try {
    const {
      search,
      category,
      rentalType,
      minPrice,
      maxPrice,
      sort = "recent",
    } = req.query;

    const filter = { status: "approved" };

    if (typeof search === "string" && search.trim()) {
      const escaped = search.trim().replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const searchRegex = new RegExp(escaped, "i");

      filter.$or = [{ name: searchRegex }, { description: searchRegex }];
    }

    if (typeof category === "string" && category.trim()) {
      filter.category = { $regex: `^${category.trim()}$`, $options: "i" };
    }

    if (typeof rentalType === "string" && rentalType.trim()) {
      filter.rentalType = rentalType;
    }

    const priceRange = {};

    if (minPrice !== undefined && minPrice !== "") {
      const minimum = Number(minPrice);

      if (!Number.isFinite(minimum) || minimum < 0) {
        return fail(res, 400, "Invalid minimum price.");
      }

      priceRange.$gte = minimum;
    }

    if (maxPrice !== undefined && maxPrice !== "") {
      const maximum = Number(maxPrice);

      if (!Number.isFinite(maximum) || maximum < 0) {
        return fail(res, 400, "Invalid maximum price.");
      }

      priceRange.$lte = maximum;
    }

    if (
      priceRange.$gte !== undefined &&
      priceRange.$lte !== undefined &&
      priceRange.$gte > priceRange.$lte
    ) {
      return fail(res, 400, "Minimum price cannot exceed maximum price.");
    }

    if (Object.keys(priceRange).length > 0) {
      filter.price = priceRange;
    }

    const sortOptions = {
      recent: { createdAt: -1 },
      "price-low": { price: 1 },
      "price-high": { price: -1 },
    };

    const equipments = await db
      .collection("equipments")
      .find(filter)
      .sort(sortOptions[sort] || sortOptions.recent)
      .toArray();

    return res.status(200).json({
      success: true,
      total: equipments.length,
      data: equipments,
    });
  } catch (error) {
    console.error("Get equipment error:", error);
    return serverError(res, "Failed to get equipment.");
  }
});

// Owner's own equipment (must stay above "/api/equipments/:id")
app.get(
  "/api/equipments/my-equipment",
  verifyToken,
  verifyOwner,
  async (req, res) => {
    try {
      const equipments = await db
        .collection("equipments")
        .find({ ownerId: req.user.id })
        .sort({ createdAt: -1 })
        .toArray();

      return res.status(200).json({
        success: true,
        total: equipments.length,
        data: equipments,
      });
    } catch (error) {
      console.error("Get owner's equipment error:", error);
      return serverError(res, "Failed to get your equipment.");
    }
  }
);

app.get("/api/equipments/:id", async (req, res) => {
  try {
    const { id } = req.params;

    if (!isValidObjectId(id)) {
      return fail(res, 400, "Invalid equipment ID.");
    }

    const equipment = await db.collection("equipments").findOne({
      _id: toObjectId(id),
      status: "approved",
    });

    if (!equipment) {
      return fail(res, 404, "Equipment not found.");
    }

    return res.status(200).json({ success: true, data: equipment });
  } catch (error) {
    console.error("Get single equipment error:", error);
    return serverError(res, "Failed to get equipment details.");
  }
});

app.post("/api/equipments", verifyToken, verifyOwner, async (req, res) => {
  try {
    const { data, error } = parseEquipmentInput(req.body);

    if (error) {
      return fail(res, 400, error);
    }

    const equipment = {
      ...data,
      image: data.image ?? "",
      ownerId: req.user.id,
      ownerName: req.user.name,
      ownerEmail: req.user.email,
      status: "pending",
      createdAt: new Date(),
      updatedAt: new Date(),
    };

    const result = await db.collection("equipments").insertOne(equipment);

    return res.status(201).json({
      success: true,
      message: "Equipment added successfully! Waiting for admin approval.",
      data: { _id: result.insertedId, ...equipment },
    });
  } catch (error) {
    console.error("Add equipment error:", error);
    return serverError(res, "Failed to add equipment.");
  }
});

app.patch(
  "/api/equipments/:id",
  verifyToken,
  verifyOwner,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!isValidObjectId(id)) {
        return fail(res, 400, "Invalid equipment ID.");
      }

      const { data: updateData, error } = parseEquipmentInput(req.body, {
        partial: true,
      });

      if (error) {
        return fail(res, 400, error);
      }

      if (Object.keys(updateData).length === 0) {
        return fail(res, 400, "No equipment information provided.");
      }

      updateData.updatedAt = new Date();

      const equipmentFilter = { _id: toObjectId(id), ownerId: req.user.id };

      const result = await db
        .collection("equipments")
        .updateOne(equipmentFilter, { $set: updateData });

      if (!result.matchedCount) {
        return fail(
          res,
          404,
          "Equipment not found or you do not own this equipment."
        );
      }

      const updatedEquipment = await db
        .collection("equipments")
        .findOne(equipmentFilter);

      return res.status(200).json({
        success: true,
        message: "Equipment updated successfully.",
        data: updatedEquipment,
      });
    } catch (error) {
      console.error("Update equipment error:", error);
      return serverError(res, "Failed to update equipment.");
    }
  }
);

app.delete(
  "/api/equipments/:id",
  verifyToken,
  verifyOwner,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!isValidObjectId(id)) {
        return fail(res, 400, "Invalid equipment ID.");
      }

      const result = await db.collection("equipments").deleteOne({
        _id: toObjectId(id),
        ownerId: req.user.id,
      });

      if (!result.deletedCount) {
        return fail(
          res,
          404,
          "Equipment not found or you do not own this equipment."
        );
      }

      return res.status(200).json({
        success: true,
        message: "Equipment deleted successfully.",
      });
    } catch (error) {
      console.error("Delete equipment error:", error);
      return serverError(res, "Failed to delete equipment.");
    }
  }
);

// ============================================
// PAYMENTS
// ============================================

app.post(
  "/api/payments/create-checkout-session",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const {
        equipmentId,
        startDate,
        endDate,
        quantity,
        contactPhone,
        address,
        notes,
      } = req.body;

      if (!isValidObjectId(equipmentId)) {
        return fail(res, 400, "Invalid equipment ID.");
      }

      if (!startDate || !endDate) {
        return fail(res, 400, "Please provide booking dates.");
      }

      const start = new Date(startDate);
      const end = new Date(endDate);

      if (Number.isNaN(start.getTime()) || Number.isNaN(end.getTime())) {
        return fail(res, 400, "Please provide valid booking dates.");
      }

      if (start <= new Date()) {
        return fail(res, 400, "Booking start date must be in the future.");
      }

      if (end <= start) {
        return fail(res, 400, "End date must be after start date.");
      }

      const bookingQuantity = Number(quantity);

      if (!Number.isInteger(bookingQuantity) || bookingQuantity < 1) {
        return fail(res, 400, "Quantity must be at least 1.");
      }

      if (
        typeof contactPhone !== "string" ||
        !contactPhone.trim() ||
        typeof address !== "string" ||
        !address.trim()
      ) {
        return fail(res, 400, "Phone number and address are required.");
      }

      if (notes !== undefined && typeof notes !== "string") {
        return fail(res, 400, "Invalid booking notes.");
      }

      const equipment = await db.collection("equipments").findOne({
        _id: toObjectId(equipmentId),
        status: "approved",
      });

      if (!equipment) {
        return fail(res, 404, "Equipment not found or not available.");
      }

      if (equipment.ownerId === req.user.id) {
        return fail(res, 403, "You cannot book your own equipment.");
      }

      if (bookingQuantity > equipment.quantity) {
        return fail(res, 400, `Only ${equipment.quantity} item(s) are available.`);
      }

      const rentalDuration = calculateRentalDuration(
        equipment.rentalType,
        start,
        end
      );

      if (!Number.isInteger(rentalDuration) || rentalDuration < 1) {
        return fail(res, 400, "Invalid rental duration.");
      }

      const totalPrice = equipment.price * rentalDuration * bookingQuantity;
      const amountInSmallestUnit = Math.round(totalPrice * 100);

      if (
        !Number.isFinite(totalPrice) ||
        totalPrice <= 0 ||
        !Number.isSafeInteger(amountInSmallestUnit) ||
        amountInSmallestUnit < 1
      ) {
        return fail(res, 400, "Invalid booking price.");
      }

      const checkoutSession = await stripe.checkout.sessions.create({
        mode: "payment",
        customer_email: req.user.email,
        client_reference_id: req.user.id,

        line_items: [
          {
            price_data: {
              currency: "bdt",
              product_data: {
                name: equipment.name,
                description: `Equipora ${equipment.rentalType} rental`,
                ...(equipment.image ? { images: [equipment.image] } : {}),
              },
              unit_amount: amountInSmallestUnit,
            },
            quantity: 1,
          },
        ],

        metadata: {
          customerId: req.user.id,
          equipmentId: equipment._id.toString(),
        },

        success_url: `${CLIENT_URL}/payment-success?session_id={CHECKOUT_SESSION_ID}`,
        cancel_url: `${CLIENT_URL}/equipment/${equipmentId}?payment=cancelled`,
      });

      await db.collection("pendingPayments").insertOne({
        sessionId: checkoutSession.id,

        equipmentId: equipment._id.toString(),
        equipmentName: equipment.name,
        equipmentImage: equipment.image || "",
        category: equipment.category,

        ownerId: equipment.ownerId,
        ownerName: equipment.ownerName || "",
        ownerEmail: equipment.ownerEmail || "",

        customerId: req.user.id,
        customerName: req.user.name,
        customerEmail: req.user.email,

        startDate: start,
        endDate: end,

        rentalType: equipment.rentalType,
        pricePerUnit: equipment.price,
        rentalDuration,
        quantity: bookingQuantity,
        totalPrice,

        contactPhone: contactPhone.trim(),
        address: address.trim(),
        notes: notes?.trim() || "",

        currency: "bdt",
        paymentStatus: "pending",
        bookingId: null,

        createdAt: new Date(),
        updatedAt: new Date(),
      });

      return res.status(201).json({
        success: true,
        message: "Checkout session created successfully.",
        data: {
          sessionId: checkoutSession.id,
          checkoutUrl: checkoutSession.url,
          totalPrice,
          currency: "bdt",
        },
      });
    } catch (error) {
      console.error("Create checkout session error:", error);
      return serverError(res, "Failed to create checkout session.");
    }
  }
);

app.get(
  "/api/payments/verify-session",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const { session_id } = req.query;

      if (typeof session_id !== "string" || !session_id.startsWith("cs_")) {
        return fail(res, 400, "Invalid checkout session ID.");
      }

      const pendingPayment = await db.collection("pendingPayments").findOne({
        sessionId: session_id,
        customerId: req.user.id,
      });

      if (!pendingPayment) {
        return fail(res, 404, "Payment session not found.");
      }

      const session = await stripe.checkout.sessions.retrieve(session_id);

      if (session.metadata?.customerId !== req.user.id) {
        return fail(res, 403, "You are not authorized to verify this payment.");
      }

      if (session.payment_status !== "paid") {
        return res.status(200).json({
          success: true,
          paid: false,
          message: "Payment has not been completed yet.",
        });
      }

      await handleSuccessfulCheckout(session);

      const booking = await db.collection("bookings").findOne({
        stripeSessionId: session.id,
        customerId: req.user.id,
      });

      if (!booking) {
        throw new Error("Paid booking could not be found.");
      }

      return res.status(200).json({
        success: true,
        paid: true,
        message: "Payment verified successfully.",
        data: { booking },
      });
    } catch (error) {
      console.error("Verify payment error:", error);
      return serverError(res, "Failed to verify payment.");
    }
  }
);

// ============================================
// CUSTOMER BOOKINGS
// ============================================

app.get(
  "/api/bookings/my-bookings",
  verifyToken,
  verifyCustomer,
  async (req, res) => {
    try {
      const bookings = await db
        .collection("bookings")
        .find({ customerId: req.user.id })
        .sort({ createdAt: -1 })
        .toArray();

      return res.status(200).json({
        success: true,
        total: bookings.length,
        data: bookings,
      });
    } catch (error) {
      console.error("Get customer bookings error:", error);
      return serverError(res, "Failed to get your bookings.");
    }
  }
);

// ============================================
// OWNER BOOKINGS
// ============================================

app.get(
  "/api/bookings/owner-requests",
  verifyToken,
  verifyOwner,
  async (req, res) => {
    try {
      // Safety net: an unpaid booking should never be in the approved state.
      await db.collection("bookings").updateMany(
        {
          ownerId: req.user.id,
          status: "approved",
          paymentStatus: { $ne: "paid" },
        },
        { $set: { status: "pending", updatedAt: new Date() } }
      );

      const bookings = await db
        .collection("bookings")
        .find({ ownerId: req.user.id })
        .sort({ createdAt: -1 })
        .toArray();

      return res.status(200).json({
        success: true,
        total: bookings.length,
        data: bookings,
      });
    } catch (error) {
      console.error("Get owner requests error:", error);
      return serverError(res, "Failed to get rental requests.");
    }
  }
);

// Approve or reject a paid booking
app.patch(
  "/api/bookings/:id/status",
  verifyToken,
  verifyOwner,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!isValidObjectId(id)) {
        return fail(res, 400, "Invalid booking ID.");
      }

      if (!["approved", "rejected"].includes(status)) {
        return fail(res, 400, "Status must be approved or rejected.");
      }

      const bookingFilter = { _id: toObjectId(id), ownerId: req.user.id };
      const booking = await db.collection("bookings").findOne(bookingFilter);

      if (!booking) {
        return fail(res, 404, "Booking not found or you do not own this booking.");
      }

      if (booking.status !== "pending") {
        return fail(res, 400, "Only pending bookings can be updated.");
      }

      if (booking.paymentStatus !== "paid") {
        return fail(
          res,
          403,
          "Payment must be completed before updating this booking."
        );
      }

      const result = await db.collection("bookings").updateOne(
        { ...bookingFilter, status: "pending", paymentStatus: "paid" },
        { $set: { status, updatedAt: new Date() } }
      );

      if (!result.modifiedCount) {
        return fail(
          res,
          409,
          "Booking status could not be updated. Please refresh."
        );
      }

      const updatedBooking = await db.collection("bookings").findOne(bookingFilter);

      return res.status(200).json({
        success: true,
        message: `Booking ${status} successfully.`,
        data: updatedBooking,
      });
    } catch (error) {
      console.error("Update owner booking status error:", error);
      return serverError(res, "Failed to update booking status.");
    }
  }
);

// Mark an approved rental as completed once its end date has passed
app.patch(
  "/api/bookings/:id/complete",
  verifyToken,
  verifyOwner,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!isValidObjectId(id)) {
        return fail(res, 400, "Invalid booking ID.");
      }

      const bookingFilter = { _id: toObjectId(id), ownerId: req.user.id };
      const booking = await db.collection("bookings").findOne(bookingFilter);

      if (!booking) {
        return fail(res, 404, "Booking not found or you do not own this booking.");
      }

      if (booking.paymentStatus !== "paid") {
        return fail(res, 403, "Unpaid bookings cannot be completed.");
      }

      if (booking.status !== "approved") {
        return fail(res, 400, "Only approved bookings can be completed.");
      }

      const endDate = new Date(booking.endDate);

      if (Number.isNaN(endDate.getTime()) || endDate.getTime() > Date.now()) {
        return fail(res, 400, "Rental cannot be completed before the end date.");
      }

      const result = await db.collection("bookings").updateOne(
        {
          ...bookingFilter,
          paymentStatus: "paid",
          status: "approved",
          endDate: { $lte: new Date() },
        },
        {
          $set: {
            status: "completed",
            completedAt: new Date(),
            updatedAt: new Date(),
          },
        }
      );

      if (!result.modifiedCount) {
        return fail(res, 409, "Booking could not be completed. Please refresh.");
      }

      const updatedBooking = await db.collection("bookings").findOne(bookingFilter);

      return res.status(200).json({
        success: true,
        message: "Rental completed successfully.",
        data: formatBooking(updatedBooking),
      });
    } catch (error) {
      console.error("Complete rental error:", error);
      return serverError(res, "Failed to complete rental.");
    }
  }
);

// ============================================
// ADMIN: USERS
// ============================================

app.get("/api/users", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const users = await db
      .collection("user")
      .find({})
      .project({
        name: 1,
        email: 1,
        image: 1,
        role: 1,
        emailVerified: 1,
        createdAt: 1,
      })
      .sort({ createdAt: -1 })
      .toArray();

    return res.status(200).json({
      success: true,
      total: users.length,
      data: users,
    });
  } catch (error) {
    console.error("Get users error:", error);
    return serverError(res, "Failed to get users.");
  }
});

app.get("/api/users/:id/role", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const user = await getUserById(req.params.id);

    if (!user) {
      return fail(res, 404, "User not found.");
    }

    return res.status(200).json({
      success: true,
      data: { role: user.role || "customer" },
    });
  } catch (error) {
    console.error("Get user role error:", error);
    return serverError(res, "Failed to get user role.");
  }
});

app.patch("/api/users/:id/role", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const userId = req.params.id;
    const { role } = req.body;

    if (!USER_ROLES.includes(role)) {
      return fail(res, 400, "Invalid role.");
    }

    if (userId === req.user.id) {
      return fail(res, 403, "You cannot change your own role.");
    }

    const result = await db.collection("user").updateOne(
      getUserIdFilter(userId),
      { $set: { role, updatedAt: new Date() } }
    );

    if (!result.matchedCount) {
      return fail(res, 404, "User not found.");
    }

    return res.status(200).json({
      success: true,
      message: "User role updated successfully.",
    });
  } catch (error) {
    console.error("Update user role error:", error);
    return serverError(res, "Failed to update user role.");
  }
});

// ============================================
// ADMIN: EQUIPMENT
// ============================================

// All equipment, including pending and rejected
app.get("/api/admin/equipments", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const equipments = await db
      .collection("equipments")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    return res.status(200).json({
      success: true,
      total: equipments.length,
      data: equipments,
    });
  } catch (error) {
    console.error("Admin get equipment error:", error);
    return serverError(res, "Failed to get all equipment.");
  }
});

app.patch(
  "/api/admin/equipments/:id/status",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!isValidObjectId(id)) {
        return fail(res, 400, "Invalid equipment ID.");
      }

      if (!["approved", "rejected"].includes(status)) {
        return fail(res, 400, "Status must be approved or rejected.");
      }

      const equipmentFilter = { _id: toObjectId(id) };

      const result = await db.collection("equipments").updateOne(
        equipmentFilter,
        { $set: { status, updatedAt: new Date() } }
      );

      if (!result.matchedCount) {
        return fail(res, 404, "Equipment not found.");
      }

      const updatedEquipment = await db
        .collection("equipments")
        .findOne(equipmentFilter);

      return res.status(200).json({
        success: true,
        message: `Equipment ${status} successfully.`,
        data: updatedEquipment,
      });
    } catch (error) {
      console.error("Admin update equipment status error:", error);
      return serverError(res, "Failed to update equipment status.");
    }
  }
);

app.delete(
  "/api/admin/equipments/:id",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;

      if (!isValidObjectId(id)) {
        return fail(res, 400, "Invalid equipment ID.");
      }

      const result = await db
        .collection("equipments")
        .deleteOne({ _id: toObjectId(id) });

      if (!result.deletedCount) {
        return fail(res, 404, "Equipment not found.");
      }

      return res.status(200).json({
        success: true,
        message: "Equipment deleted successfully.",
      });
    } catch (error) {
      console.error("Admin delete equipment error:", error);
      return serverError(res, "Failed to delete equipment.");
    }
  }
);

// ============================================
// ADMIN: BOOKINGS
// ============================================

app.get("/api/bookings/admin/all", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const bookings = await db
      .collection("bookings")
      .find({})
      .sort({ createdAt: -1 })
      .toArray();

    return res.status(200).json({
      success: true,
      total: bookings.length,
      data: bookings.map(formatBooking),
    });
  } catch (error) {
    console.error("Admin get bookings error:", error);
    return serverError(res, "Failed to get all bookings.");
  }
});

app.patch(
  "/api/bookings/admin/:id/status",
  verifyToken,
  verifyAdmin,
  async (req, res) => {
    try {
      const { id } = req.params;
      const { status } = req.body;

      if (!isValidObjectId(id)) {
        return fail(res, 400, "Invalid booking ID.");
      }

      if (!["approved", "rejected", "cancelled"].includes(status)) {
        return fail(res, 400, "Invalid booking status.");
      }

      const bookingFilter = { _id: toObjectId(id) };
      const booking = await db.collection("bookings").findOne(bookingFilter);

      if (!booking) {
        return fail(res, 404, "Booking not found.");
      }

      if (booking.status !== "pending") {
        return fail(res, 400, "Only pending bookings can be updated.");
      }

      if (status === "approved" && booking.paymentStatus !== "paid") {
        return fail(res, 403, "Unpaid bookings cannot be approved.");
      }

      const updateFilter = { ...bookingFilter, status: "pending" };

      if (status === "approved") {
        updateFilter.paymentStatus = "paid";
      }

      const result = await db.collection("bookings").updateOne(
        updateFilter,
        { $set: { status, updatedAt: new Date() } }
      );

      if (!result.modifiedCount) {
        return fail(
          res,
          409,
          "Booking could not be updated. Please refresh and try again."
        );
      }

      const updatedBooking = await db.collection("bookings").findOne(bookingFilter);

      return res.status(200).json({
        success: true,
        message: `Booking ${status} successfully.`,
        data: formatBooking(updatedBooking),
      });
    } catch (error) {
      console.error("Admin update booking error:", error);
      return serverError(res, "Failed to update booking status.");
    }
  }
);

// ============================================
// DASHBOARD ANALYTICS
// ============================================

// Returns the last 6 months as [{ key: "2026-06", label: "Jun", total: 0 }, ...]
const getLastSixMonths = () => {
  const now = new Date();

  return Array.from({ length: 6 }, (_, index) => {
    const date = new Date(
      Date.UTC(now.getUTCFullYear(), now.getUTCMonth() - 5 + index, 1)
    );

    const year = date.getUTCFullYear();
    const month = String(date.getUTCMonth() + 1).padStart(2, "0");

    return {
      key: `${year}-${month}`,
      label: date.toLocaleString("en-US", { month: "short", timeZone: "UTC" }),
      total: 0,
    };
  });
};

// Fills each month with its matching aggregation result (or 0).
const fillMonths = (months, results) =>
  months.map((month) => ({
    ...month,
    total: results.find((item) => item._id === month.key)?.total || 0,
  }));

// Groups documents by month of the given date field and sums either
// a count or an amount field.
const monthlyTotals = (collection, match, dateField, sumField) =>
  db
    .collection(collection)
    .aggregate([
      { $match: match },
      {
        $group: {
          _id: { $dateToString: { format: "%Y-%m", date: `$${dateField}` } },
          total: { $sum: sumField ? `$${sumField}` : 1 },
        },
      },
    ])
    .toArray();

app.get("/api/admin/analytics", verifyToken, verifyAdmin, async (req, res) => {
  try {
    const months = getLastSixMonths();
    const firstMonth = new Date(`${months[0].key}-01T00:00:00.000Z`);

    const [
      totalUsers,
      totalCustomers,
      totalOwners,
      totalEquipment,
      pendingEquipment,
      approvedEquipment,
      totalBookings,
      pendingBookings,
      approvedBookings,
      completedBookings,
      revenueResult,
      monthlyBookingsResult,
      monthlyRevenueResult,
    ] = await Promise.all([
      db.collection("user").countDocuments(),
      db.collection("user").countDocuments({ role: "customer" }),
      db.collection("user").countDocuments({ role: "owner" }),

      db.collection("equipments").countDocuments(),
      db.collection("equipments").countDocuments({ status: "pending" }),
      db.collection("equipments").countDocuments({ status: "approved" }),

      db.collection("bookings").countDocuments(),
      db.collection("bookings").countDocuments({ status: "pending" }),
      db.collection("bookings").countDocuments({ status: "approved" }),
      db.collection("bookings").countDocuments({ status: "completed" }),

      db
        .collection("transactions")
        .aggregate([
          { $match: { paymentStatus: "paid" } },
          {
            $group: {
              _id: null,
              totalRevenue: { $sum: "$amount" },
              totalTransactions: { $sum: 1 },
            },
          },
        ])
        .toArray(),

      monthlyTotals("bookings", { createdAt: { $gte: firstMonth } }, "createdAt"),

      monthlyTotals(
        "transactions",
        { paymentStatus: "paid", paidAt: { $gte: firstMonth } },
        "paidAt",
        "amount"
      ),
    ]);

    const revenue = revenueResult[0] || {
      totalRevenue: 0,
      totalTransactions: 0,
    };

    return res.status(200).json({
      success: true,
      data: {
        overview: {
          totalUsers,
          totalCustomers,
          totalOwners,
          totalEquipment,
          pendingEquipment,
          approvedEquipment,
          totalBookings,
          pendingBookings,
          approvedBookings,
          completedBookings,
          totalRevenue: revenue.totalRevenue,
          totalTransactions: revenue.totalTransactions,
        },
        monthlyBookings: fillMonths(months, monthlyBookingsResult),
        monthlyRevenue: fillMonths(months, monthlyRevenueResult),
      },
    });
  } catch (error) {
    console.error("Admin analytics error:", error);
    return serverError(res, "Failed to get admin analytics.");
  }
});

app.get("/api/owner/analytics", verifyToken, verifyOwner, async (req, res) => {
  try {
    const ownerId = req.user.id;
    const months = getLastSixMonths();
    const firstMonth = new Date(`${months[0].key}-01T00:00:00.000Z`);

    const countBookings = (status) =>
      db.collection("bookings").countDocuments({ ownerId, status });

    const countEquipment = (status) =>
      db.collection("equipments").countDocuments({ ownerId, status });

    const [
      totalEquipment,
      pendingEquipment,
      approvedEquipment,
      totalBookings,
      pendingBookings,
      approvedBookings,
      completedBookings,
      earningsResult,
      monthlyEarningsResult,
    ] = await Promise.all([
      db.collection("equipments").countDocuments({ ownerId }),
      countEquipment("pending"),
      countEquipment("approved"),

      db.collection("bookings").countDocuments({ ownerId }),
      countBookings("pending"),
      countBookings("approved"),
      countBookings("completed"),

      db
        .collection("transactions")
        .aggregate([
          { $match: { ownerId, paymentStatus: "paid" } },
          {
            $group: {
              _id: null,
              totalEarnings: { $sum: "$amount" },
              totalTransactions: { $sum: 1 },
            },
          },
        ])
        .toArray(),

      monthlyTotals(
        "transactions",
        { ownerId, paymentStatus: "paid", paidAt: { $gte: firstMonth } },
        "paidAt",
        "amount"
      ),
    ]);

    const earnings = earningsResult[0] || {
      totalEarnings: 0,
      totalTransactions: 0,
    };

    return res.status(200).json({
      success: true,
      data: {
        overview: {
          totalEquipment,
          pendingEquipment,
          approvedEquipment,
          totalBookings,
          pendingBookings,
          approvedBookings,
          completedBookings,
          totalEarnings: earnings.totalEarnings,
          totalTransactions: earnings.totalTransactions,
        },
        monthlyEarnings: fillMonths(months, monthlyEarningsResult),
      },
    });
  } catch (error) {
    console.error("Owner analytics error:", error);
    return serverError(res, "Failed to get owner analytics.");
  }
});

// ============================================
// STARTUP TASKS
// ============================================

const createPaymentIndexes = async () => {
  await db.collection("bookings").createIndex(
    { stripeSessionId: 1 },
    {
      unique: true,
      partialFilterExpression: { stripeSessionId: { $type: "string" } },
    }
  );

  await db
    .collection("transactions")
    .createIndex({ stripeSessionId: 1 }, { unique: true });

  await db
    .collection("pendingPayments")
    .createIndex({ sessionId: 1 }, { unique: true });

  console.log("Payment Database Indexes Created Successfully!");
};

// Resets old unpaid bookings that were wrongly marked as approved.
const fixUnpaidApprovedBookings = async () => {
  const result = await db.collection("bookings").updateMany(
    { status: "approved", paymentStatus: { $ne: "paid" } },
    { $set: { status: "pending", updatedAt: new Date() } }
  );

  console.log(`Unpaid Approved Bookings Fixed: ${result.modifiedCount}`);
};

// ============================================
// START SERVER
// ============================================

const startServer = async () => {
  try {
    await connectDB();
    await createPaymentIndexes();
    await fixUnpaidApprovedBookings();

    httpServer = app.listen(PORT, () => {
      console.log(`Equipora Server running on port ${PORT}`);
      console.log(`JWT JWKS URL: ${AUTH_BASE_URL}/api/auth/jwks`);
    });
  } catch (error) {
    console.error("Server Startup Error:", error);
    process.exit(1);
  }
};

const shutdown = async (signal) => {
  console.log(`${signal} received. Closing Equipora Server...`);

  try {
    if (httpServer) {
      await new Promise((resolve, reject) => {
        httpServer.close((error) => (error ? reject(error) : resolve()));
      });
    }

    await mongoClient.close();
    process.exit(0);
  } catch (error) {
    console.error("Server shutdown error:", error);
    process.exit(1);
  }
};

process.once("SIGINT", () => shutdown("SIGINT"));
process.once("SIGTERM", () => shutdown("SIGTERM"));

startServer();

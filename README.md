# Equipora Server

Backend API for the Equipora equipment rental platform. The service uses
Express, MongoDB, Better Auth, and Stripe Checkout.

## Requirements

- Node.js 20 or newer
- MongoDB instance
- Stripe account and API keys

## Setup

1. Install dependencies with `npm install`.
2. Copy `.env.example` to `.env` and provide the required values.
3. Start the development server with `npm run dev`, or use `npm start`.

The API listens on port 5000 by default. Set `PORT` to change it. The root
endpoint (`GET /`) returns a basic service status response.

## Authentication

Better Auth serves its endpoints under `/api/auth`. Protected API routes expect
a Better Auth JWT in the `Authorization: Bearer <token>` header. User roles are
`customer`, `owner`, and `admin`; new registrations are restricted to customer
or owner roles.

## API areas

- `/api/equipments` — approved equipment search and owner inventory management
- `/api/payments` — Stripe Checkout, webhook processing, and session verification
- `/api/bookings` — customer rentals and owner booking decisions
- `/api/users` — profiles and admin user management
- `/api/admin` — equipment moderation and platform analytics
- `/api/owner/analytics` — owner inventory and earnings summaries

JSON errors use `{ "success": false, "message": "..." }`. Successful
responses use a `success` flag and return resource data in `data` where
applicable.

## Payment webhook

Configure a Stripe webhook endpoint at `/api/payments/webhook` and set
`STRIPE_WEBHOOK_SECRET`. The endpoint verifies Stripe signatures against the
raw request body. The success redirect is only a user-facing confirmation;
payment records are created after Stripe confirms payment.

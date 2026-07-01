import crypto from "crypto";

import redis from "../config/redis.js";

import ApiErrors from "../helpers/ApiErrors.js";
import ApiResponse from "../helpers/ApiResponse.js";
import AsyncHandler from "../helpers/AsyncHandler.js";

// ── Constants ──────────────────────────────────────────────────────────────
const CACHE_TTL = 60 * 10; // 10 minutes

// ── Keyword Maps ───────────────────────────────────────────────────────────

const PHISHING_KEYWORDS = [
  "otp", "pin", "password", "পিন", "ওটিপি", "পাসওয়ার্ড",
  "blocked", "suspend", "verify your account", "share your",
  "someone called", "কেউ ফোন করেছে", "account block", "একাউন্ট ব্লক",
  "asked for my otp", "asked for my pin", "ওটিপি চেয়েছে",
  "fraud", "scam", "fake call", "phishing",
];

const WRONG_TRANSFER_KEYWORDS = [
  "wrong number", "wrong person", "wrong recipient", "ভুল নম্বরে",
  "ভুল মানুষকে", "sent to wrong", "transferred to wrong",
  "wrong transfer", "ভুল ট্রান্সফার", "typed it wrong",
  "didn't get it", "পায়নি", "সে পায়নি",
];

const PAYMENT_FAILED_KEYWORDS = [
  "payment failed", "failed", "but my balance was deducted",
  "balance deducted", "পেমেন্ট ফেল", "ব্যালেন্স কেটে নিয়েছে",
  "showed failed", "still deducted", "transaction failed",
  "recharge failed", "পেমেন্ট হয়নি",
];

const REFUND_KEYWORDS = [
  "refund", "রিফান্ড", "money back", "টাকা ফেরত",
  "return my money", "give back", "cancel", "changed my mind",
  "don't want", "want to cancel",
];

const DUPLICATE_KEYWORDS = [
  "duplicate", "twice", "double", "charged twice", "deducted twice",
  "paid twice", "two times", "দুইবার", "দ্বিগুণ", "double charge",
  "same payment", "again deducted",
];

const MERCHANT_SETTLEMENT_KEYWORDS = [
  "settlement", "settle", "merchant", "sales not settled",
  "settlement delay", "সেটেলমেন্ট", "পেমেন্ট পাইনি",
  "not received settlement", "settlement pending",
];

const AGENT_CASHIN_KEYWORDS = [
  "cash in", "cash-in", "cashin", "ক্যাশ ইন", "এজেন্ট",
  "agent", "balance not updated", "ব্যালেন্সে আসেনি",
  "didn't receive", "not reflected", "balance নেই",
  "টাকা আসেনি", "agent sent but",
];

// ── Helpers ────────────────────────────────────────────────────────────────

const containsAny = (text, keywords) => {
  const lower = text.toLowerCase();
  return keywords.some((kw) => lower.includes(kw.toLowerCase()));
};

const extractAmountFromComplaint = (complaint) => {
  // Match patterns like "5000 taka", "৳5000", "BDT 1200", "2000 টাকা", "1,200"
  const patterns = [
    /(\d[\d,]*)\s*(taka|bdt|৳|টাকা)/gi,
    /(taka|bdt|৳|টাকা)\s*(\d[\d,]*)/gi,
    /\b(\d{3,6})\b/g, // fallback: standalone 3-6 digit numbers
  ];
  for (const pattern of patterns) {
    const match = pattern.exec(complaint);
    if (match) {
      const raw = (match[1] || match[2]).replace(/,/g, "");
      const num = parseFloat(raw);
      if (!isNaN(num) && num > 0) return num;
    }
  }
  return null;
};

// Find the transaction most likely referenced by the complaint
const findRelevantTransaction = (complaint, transaction_history) => {
  if (!transaction_history || transaction_history.length === 0) return null;

  const amount = extractAmountFromComplaint(complaint);
  const lower = complaint.toLowerCase();

  // 1. Explicit transaction ID mention
  for (const tx of transaction_history) {
    if (lower.includes(tx.transaction_id.toLowerCase())) return tx;
  }

  // 2. Amount match — prefer failed/pending over completed for problem cases
  if (amount) {
    const amountMatches = transaction_history.filter(
      (tx) => Math.abs(tx.amount - amount) < 1
    );
    if (amountMatches.length === 1) return amountMatches[0];
    if (amountMatches.length > 1) {
      // Prefer failed/pending
      const problematic = amountMatches.find(
        (tx) => tx.status === "failed" || tx.status === "pending"
      );
      return problematic || null; // ambiguous if all completed
    }
  }

  // 3. Single transaction in history → most likely the one
  if (transaction_history.length === 1) return transaction_history[0];

  // 4. Type-based hints
  if (containsAny(lower, ["cash in", "cashin", "ক্যাশ ইন", "cash-in"])) {
    const cashIn = transaction_history.find((tx) => tx.type === "cash_in");
    if (cashIn) return cashIn;
  }
  if (containsAny(lower, ["settlement", "সেটেলমেন্ট"])) {
    const settlement = transaction_history.find((tx) => tx.type === "settlement");
    if (settlement) return settlement;
  }
  if (containsAny(lower, ["payment", "bill", "recharge", "পেমেন্ট"])) {
    const payment = transaction_history.find((tx) => tx.type === "payment");
    if (payment) return payment;
  }

  return null;
};

// Determine case_type from complaint text
const detectCaseType = (complaint) => {
  if (containsAny(complaint, PHISHING_KEYWORDS)) return "phishing_or_social_engineering";
  if (containsAny(complaint, DUPLICATE_KEYWORDS)) return "duplicate_payment";
  if (containsAny(complaint, AGENT_CASHIN_KEYWORDS)) return "agent_cash_in_issue";
  if (containsAny(complaint, MERCHANT_SETTLEMENT_KEYWORDS)) return "merchant_settlement_delay";
  if (containsAny(complaint, WRONG_TRANSFER_KEYWORDS)) return "wrong_transfer";
  if (containsAny(complaint, PAYMENT_FAILED_KEYWORDS)) return "payment_failed";
  if (containsAny(complaint, REFUND_KEYWORDS)) return "refund_request";
  return "other";
};

// Determine department from case_type and user_type
const detectDepartment = (case_type, user_type) => {
  const map = {
    phishing_or_social_engineering: "fraud_risk",
    duplicate_payment: "payments_ops",
    payment_failed: "payments_ops",
    wrong_transfer: "dispute_resolution",
    agent_cash_in_issue: "agent_operations",
    merchant_settlement_delay: "merchant_operations",
    refund_request: "customer_support",
    other: "customer_support",
  };
  // Merchant complaints always go to merchant_operations unless it's fraud
  if (user_type === "merchant" && case_type !== "phishing_or_social_engineering") {
    return "merchant_operations";
  }
  return map[case_type] || "customer_support";
};

// Determine severity
const detectSeverity = (case_type, relevant_tx, complaint) => {
  if (case_type === "phishing_or_social_engineering") return "critical";

  const amount = relevant_tx?.amount ?? extractAmountFromComplaint(complaint) ?? 0;

  if (case_type === "wrong_transfer") {
    return amount >= 5000 ? "high" : "medium";
  }
  if (case_type === "payment_failed" || case_type === "duplicate_payment") {
    return amount >= 1000 ? "high" : "medium";
  }
  if (case_type === "agent_cash_in_issue") return "high";
  if (case_type === "merchant_settlement_delay") return "medium";
  if (case_type === "refund_request") return "low";
  return "low";
};

// Determine evidence_verdict
const detectEvidenceVerdict = (case_type, relevant_tx, transaction_history, complaint) => {
  if (!relevant_tx) return "insufficient_data";

  // Phishing: no transaction expected
  if (case_type === "phishing_or_social_engineering") return "insufficient_data";

  const status = relevant_tx.status;

  if (case_type === "wrong_transfer") {
    // Check if same counterparty appears multiple times (inconsistent pattern)
    const sameCounterparty = transaction_history.filter(
      (tx) => tx.counterparty === relevant_tx.counterparty && tx.transaction_id !== relevant_tx.transaction_id
    );
    if (sameCounterparty.length >= 2) return "inconsistent";
    return status === "completed" ? "consistent" : "insufficient_data";
  }

  if (case_type === "payment_failed") {
    return status === "failed" ? "consistent" : "inconsistent";
  }

  if (case_type === "duplicate_payment") {
    // Check for near-duplicate transactions (same amount, same counterparty, close timestamps)
    const similar = transaction_history.filter(
      (tx) =>
        tx.transaction_id !== relevant_tx.transaction_id &&
        tx.amount === relevant_tx.amount &&
        tx.counterparty === relevant_tx.counterparty
    );
    return similar.length > 0 ? "consistent" : "inconsistent";
  }

  if (case_type === "agent_cash_in_issue") {
    return status === "pending" || status === "failed" ? "consistent" : "inconsistent";
  }

  if (case_type === "merchant_settlement_delay") {
    return status === "pending" ? "consistent" : "insufficient_data";
  }

  if (case_type === "refund_request") {
    return status === "completed" ? "consistent" : "insufficient_data";
  }

  return "insufficient_data";
};

// Should require human review?
const needsHumanReview = (case_type, evidence_verdict, severity, relevant_tx) => {
  if (["critical", "high"].includes(severity)) return true;
  if (["phishing_or_social_engineering", "wrong_transfer", "duplicate_payment"].includes(case_type)) return true;
  if (evidence_verdict === "inconsistent") return true;
  if (relevant_tx?.status === "pending") return true;
  return false;
};

// Find duplicate tx (second one is the duplicate)
const findDuplicateTx = (transaction_history) => {
  const seen = {};
  for (const tx of transaction_history) {
    const key = `${tx.amount}-${tx.counterparty}`;
    if (seen[key]) return tx; // second occurrence is the duplicate
    seen[key] = tx;
  }
  return null;
};

// Detect complaint language
const detectLanguage = (complaint, provided) => {
  if (provided && ["en", "bn", "mixed"].includes(provided)) return provided;
  const banglaPattern = /[\u0980-\u09FF]/;
  const hasEnglish = /[a-zA-Z]/.test(complaint);
  const hasBangla = banglaPattern.test(complaint);
  if (hasBangla && hasEnglish) return "mixed";
  if (hasBangla) return "bn";
  return "en";
};

// ── Build Response Texts ───────────────────────────────────────────────────

const buildAgentSummary = (case_type, relevant_tx, complaint, transaction_history) => {
  if (case_type === "phishing_or_social_engineering") {
    return "Customer reports a suspicious call/message asking for credentials. Likely social engineering attempt. No transaction involved.";
  }
  if (!relevant_tx) {
    return "Customer complaint is vague or ambiguous. Insufficient information to identify a specific transaction. Clarification needed.";
  }

  const txRef = `${relevant_tx.transaction_id} (${relevant_tx.amount} BDT to ${relevant_tx.counterparty})`;

  const summaries = {
    wrong_transfer: `Customer reports sending ${relevant_tx.amount} BDT via ${txRef} to an unintended recipient. Status: ${relevant_tx.status}.`,
    payment_failed: `Customer attempted a ${relevant_tx.amount} BDT payment (${txRef}) which shows as ${relevant_tx.status}, but reports balance was deducted.`,
    refund_request: `Customer requests refund of ${relevant_tx.amount} BDT for completed payment ${txRef}.`,
    duplicate_payment: `Possible duplicate payment detected. Two identical ${relevant_tx.amount} BDT payments to ${relevant_tx.counterparty} found in history. ${relevant_tx.transaction_id} appears to be the duplicate.`,
    merchant_settlement_delay: `Merchant reports ${relevant_tx.amount} BDT settlement (${relevant_tx.transaction_id}) is delayed. Status is ${relevant_tx.status}.`,
    agent_cash_in_issue: `Customer reports ${relevant_tx.amount} BDT cash-in via ${relevant_tx.counterparty} (${relevant_tx.transaction_id}) not reflected in balance. Status: ${relevant_tx.status}.`,
    other: `Customer submitted a support request. Relevant transaction: ${txRef}. Manual review may be needed.`,
  };

  return summaries[case_type] || summaries["other"];
};

const buildNextAction = (case_type, relevant_tx, evidence_verdict) => {
  if (evidence_verdict === "insufficient_data" && !relevant_tx) {
    return "Reply to customer asking for specific details: transaction ID, amount, approximate time, and a brief description of the issue.";
  }

  const txId = relevant_tx?.transaction_id ?? "the reported transaction";

  const actions = {
    phishing_or_social_engineering: "Escalate to fraud_risk team immediately. Log the suspicious number/source for pattern analysis. Remind customer never to share credentials.",
    wrong_transfer: `Verify ${txId} details with the customer and initiate the wrong-transfer dispute workflow per policy.`,
    payment_failed: `Investigate ${txId} ledger status. If balance was deducted on a failed payment, initiate the automatic reversal flow within standard SLA.`,
    refund_request: "Inform customer that refund eligibility depends on merchant policy. Provide guidance on contacting the merchant directly.",
    duplicate_payment: `Verify duplicate with payments_ops. If biller confirms only one payment received, initiate reversal of ${txId}.`,
    merchant_settlement_delay: `Route to merchant_operations to verify settlement batch status for ${txId}. Communicate revised ETA to merchant if delayed.`,
    agent_cash_in_issue: `Investigate ${txId} pending status with agent operations. Confirm settlement state and resolve within standard cash-in SLA.`,
    other: "Route to customer_support for manual review. Request additional details if needed.",
  };

  return actions[case_type] || actions["other"];
};

const buildCustomerReply = (case_type, relevant_tx, lang) => {
  const txRef = relevant_tx ? `transaction ${relevant_tx.transaction_id}` : "your request";
  const safeClosing =
    lang === "bn"
      ? "অনুগ্রহ করে কারো সাথে আপনার পিন বা ওটিপি শেয়ার করবেন না।"
      : "Please do not share your PIN or OTP with anyone.";

  const officialChannel =
    lang === "bn"
      ? "অফিসিয়াল সাপোর্ট চ্যানেলের মাধ্যমে আপনাকে জানানো হবে।"
      : "We will contact you through official support channels.";

  if (case_type === "phishing_or_social_engineering") {
    return lang === "bn"
      ? `আমরা কখনও আপনার পিন, ওটিপি বা পাসওয়ার্ড চাই না। কাউকে এই তথ্য শেয়ার করবেন না, এমনকি আমাদের নামেও না। আমাদের ফ্রড টিম এই বিষয়ে অবহিত হয়েছে।`
      : `Thank you for reaching out before sharing any information. We never ask for your PIN, OTP, or password under any circumstances. Please do not share these with anyone, even if they claim to be from us. Our fraud team has been notified of this incident.`;
  }

  if (!relevant_tx) {
    return lang === "bn"
      ? `আপনার সাথে যোগাযোগ করার জন্য ধন্যবাদ। আপনাকে দ্রুত সাহায্য করতে দয়া করে লেনদেন আইডি, পরিমাণ এবং কী সমস্যা হয়েছে তা জানান। ${safeClosing}`
      : `Thank you for reaching out. To help you faster, please share the transaction ID, the amount involved, and a short description of what went wrong. ${safeClosing}`;
  }

  const replies = {
    wrong_transfer:
      lang === "bn"
        ? `আপনার ${txRef} সম্পর্কে আমরা অবগত হয়েছি। আমাদের বিরোধ নিষ্পত্তি দল বিষয়টি পর্যালোচনা করবে এবং ${officialChannel} ${safeClosing}`
        : `We have noted your concern about ${txRef}. Our dispute team will review the case and contact you through official support channels. ${safeClosing}`,

    payment_failed:
      lang === "bn"
        ? `আমরা ${txRef}-এর সমস্যাটি নোট করেছি। আমাদের পেমেন্ট দল তদন্ত করবে এবং যেকোনো যোগ্য পরিমাণ অফিসিয়াল চ্যানেলের মাধ্যমে ফেরত দেওয়া হবে। ${safeClosing}`
        : `We have noted that ${txRef} may have caused an unexpected balance deduction. Our payments team will review the case and any eligible amount will be returned through official channels. ${safeClosing}`,

    refund_request:
      `Thank you for reaching out. Refunds for completed payments depend on the merchant's own policy. We recommend contacting the merchant directly. If you need help reaching them, please reply and we will guide you. ${safeClosing}`,

    duplicate_payment:
      lang === "bn"
        ? `আমরা ${txRef}-এর সম্ভাব্য ডুপ্লিকেট পেমেন্ট নোট করেছি। আমাদের পেমেন্ট দল বিলারের সাথে যাচাই করবে এবং যেকোনো যোগ্য পরিমাণ অফিসিয়াল চ্যানেলের মাধ্যমে ফেরত দেওয়া হবে। ${safeClosing}`
        : `We have noted the possible duplicate payment for ${txRef}. Our payments team will verify with the biller and any eligible amount will be returned through official channels. ${safeClosing}`,

    merchant_settlement_delay:
      `We have noted your concern about settlement ${txRef}. Our merchant operations team will check the batch status and update you on the expected settlement time through official channels.`,

    agent_cash_in_issue:
      lang === "bn"
        ? `আপনার ${txRef} বিষয়ে আমরা অবগত হয়েছি। আমাদের এজেন্ট অপারেশন্স দল এটি দ্রুত যাচাই করবে এবং ${officialChannel} ${safeClosing}`
        : `We have noted your concern about ${txRef}. Our agent operations team will investigate and contact you through official support channels. ${safeClosing}`,

    other:
      `Thank you for contacting us. We have received your request regarding ${txRef} and our team will review it shortly. ${officialChannel} ${safeClosing}`,
  };

  return replies[case_type] || replies["other"];
};

const buildReasonCodes = (case_type, evidence_verdict, relevant_tx, transaction_history) => {
  const codes = [case_type];
  if (relevant_tx) codes.push("transaction_match");
  if (evidence_verdict === "inconsistent") codes.push("evidence_inconsistent");
  if (evidence_verdict === "insufficient_data") codes.push("insufficient_data");
  if (relevant_tx?.status === "pending") codes.push("pending_transaction");
  if (relevant_tx?.status === "failed") codes.push("failed_transaction");

  if (case_type === "wrong_transfer") {
    const sameCounterparty = transaction_history?.filter(
      (tx) => tx.counterparty === relevant_tx?.counterparty && tx.transaction_id !== relevant_tx?.transaction_id
    );
    if (sameCounterparty?.length >= 2) codes.push("established_recipient_pattern");
  }

  if (case_type === "phishing_or_social_engineering") codes.push("credential_protection", "critical_escalation");
  if (case_type === "duplicate_payment") codes.push("biller_verification_required");
  if (case_type === "merchant_settlement_delay") codes.push("delay", "pending");
  return codes;
};

const calcConfidence = (case_type, evidence_verdict, relevant_tx) => {
  if (case_type === "phishing_or_social_engineering") return 0.95;
  if (!relevant_tx) return 0.5;
  if (evidence_verdict === "consistent") return relevant_tx ? 0.9 : 0.7;
  if (evidence_verdict === "inconsistent") return 0.75;
  return 0.6;
};

// ── Cache Key ──────────────────────────────────────────────────────────────
const generateCacheKey = (body) => {
  const payload = JSON.stringify({
    complaint: body.complaint,
    transaction_history: body.transaction_history ?? [],
    user_type: body.user_type ?? "unknown",
    campaign_context: body.campaign_context ?? null,
  });
  return `ticket:${crypto.createHash("md5").update(payload).digest("hex")}`;
};

// ── Controller ─────────────────────────────────────────────────────────────
const analyzeTicket = AsyncHandler(async (req, res) => {
  const body = req.body;

  if (!body?.ticket_id || typeof body.ticket_id !== "string" || !body.ticket_id.trim()) {
    throw new ApiErrors(400, "Missing or invalid required field: ticket_id");
  }
  if (!body?.complaint || typeof body.complaint !== "string" || !body.complaint.trim()) {
    throw new ApiErrors(422, "Missing or empty required field: complaint");
  }

  const {
    ticket_id,
    complaint,
    language: langInput,
    user_type = "customer",
    transaction_history = [],
  } = body;

  // Cache check
  const cacheKey = generateCacheKey(body);
  const cached = await redis.get(cacheKey);
  if (cached) {
    const parsed = JSON.parse(cached);
    parsed.ticket_id = ticket_id;
    return res
      .status(200)
      .json(new ApiResponse(200, parsed, "Ticket analyzed successfully (cached)"));
  }

  // ── Core Investigation Logic ─────────────────────────────────────────────
  const lang = detectLanguage(complaint, langInput);
  const case_type = detectCaseType(complaint);

  // For duplicate payments, pick the second (duplicate) transaction
  let relevant_tx =
    case_type === "duplicate_payment"
      ? findDuplicateTx(transaction_history)
      : findRelevantTransaction(complaint, transaction_history);

  // If complaint is vague and no amount match, keep relevant_tx null
  const evidence_verdict = detectEvidenceVerdict(
    case_type,
    relevant_tx,
    transaction_history,
    complaint
  );

  const department = detectDepartment(case_type, user_type);
  const severity = detectSeverity(case_type, relevant_tx, complaint);
  const human_review_required = needsHumanReview(case_type, evidence_verdict, severity, relevant_tx);
  const confidence = calcConfidence(case_type, evidence_verdict, relevant_tx);
  const reason_codes = buildReasonCodes(case_type, evidence_verdict, relevant_tx, transaction_history);

  const result = {
    ticket_id,
    relevant_transaction_id: relevant_tx?.transaction_id ?? null,
    evidence_verdict,
    case_type,
    severity,
    department,
    agent_summary: buildAgentSummary(case_type, relevant_tx, complaint, transaction_history),
    recommended_next_action: buildNextAction(case_type, relevant_tx, evidence_verdict),
    customer_reply: buildCustomerReply(case_type, relevant_tx, lang),
    human_review_required,
    confidence,
    reason_codes,
  };

  // Cache result
  await redis.set(cacheKey, JSON.stringify(result), "EX", CACHE_TTL);

  return res
    .status(200)
    .json(new ApiResponse(200, result, "Ticket analyzed successfully"));
});

export default analyzeTicket;

import dotenv from 'dotenv';
dotenv.config();

import { GoogleGenerativeAI } from "@google/generative-ai";

if (!process.env.GEMINI_API_KEY) {
  throw new Error("GEMINI_API_KEY is missing in the environment");
}

const genAI = new GoogleGenerativeAI(process.env.GEMINI_API_KEY);
export default genAI;
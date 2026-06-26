import express from 'express'
import cors from 'cors'
import cookieParser from 'cookie-parser'
import errorHandler from './helpers/ErrorHandler.js'
import analyzeTicket from './controller/analyzeTicket.js'

const app = express()

app.use(cors({
    origin: process.env.CORS_ORIGIN,
    credentials: true
}))

app.use(cookieParser())

app.use(express.json())
app.use(express.urlencoded({ extended: true }))

app.get("/health", (req, res) => {
    res.status(200).json({ status: "ok" });
});

app.post("/analyze-ticket", analyzeTicket);

app.get('/', (req, res) => {
    res.send("sust server is running ...")
})

app.use(errorHandler)

export default app
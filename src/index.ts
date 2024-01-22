import express from "express";
import morgan from "morgan";
import bodyParser from "body-parser";
import { router } from "./routes/userRouter";

const app = express();
const port = process.env.PORT;

app.use(morgan("dev"));
app.use(bodyParser.json());
app.use(bodyParser.urlencoded({ extended: true }));
app.use(router);

app.listen(port, () => console.log(`http://localhost:${port}`));

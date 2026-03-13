import http from "node:http";
import app from "./api/index.js";

const port = Number(process.env.PORT || 3000);

http.createServer(app).listen(port, () => {
  console.log(`Server listening on http://localhost:${port}`);
});

// Run the server, implement logging, and ensure server is running properly
import app from './app.js';

const PORT = process.env.PORT || 8000;

app.listen(PORT, () => {
  console.log(`Listening on http://localhost:${PORT}...`);
});

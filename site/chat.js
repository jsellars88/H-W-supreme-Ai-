
export default async function handler(req, res) {
  if (req.method === 'POST') {
    const { message } = req.body;
    const reply = `Echo: ${message}`; // Replace with real AI call
    res.status(200).json({ reply });
  } else {
    res.status(405).json({ message: 'Method not allowed' });
  }
}

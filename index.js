
import { useState } from 'react';

export default function Home() {
  const [input, setInput] = useState('');
  const [response, setResponse] = useState('');

  const handleSubmit = async (e) => {
    e.preventDefault();
    const res = await fetch('/api/chat', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ message: input }),
    });
    const data = await res.json();
    setResponse(data.reply);
  };

  return (
    <div style={{ padding: 20 }}>
      <h1>Holmes & Watson Supreme AI</h1>
      <form onSubmit={handleSubmit}>
        <input
          type="text"
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Ask me anything..."
        />
        <button type="submit">Send</button>
      </form>
      <p><strong>AI:</strong> {response}</p>
    </div>
  );
}

import React from 'react';
import './App.css'
import { Outlet, Link } from 'react-router-dom';

function App() {
  return (
    <div className="app-container">
      <header>
        <nav>
          <ul style={{ listStyleType: 'none', margin: 0, padding: 0, display: 'flex', gap: '15px' }}>
            <li><Link to="/">Home</Link></li>
            <li><Link to="/register">Register</Link></li>
            <li><Link to="/login">Login</Link></li>
            <li><Link to="/dashboard">Dashboard (Test)</Link></li>
          </ul>
        </nav>
      </header>

      <main>
        <Outlet />
      </main>

      <footer>
        <p>&copy; {new Date().getFullYear()} Konoha Minecraft Portal</p>
      </footer>
    </div>    
  );
}

export default App

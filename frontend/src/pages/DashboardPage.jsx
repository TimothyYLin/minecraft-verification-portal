import React, { useState } from 'react';
import { useAuth } from '@/hooks/useAuth';
import { linkMinecraftUsername } from '@/services/apiService';

import formStyles from '@/components/Form/Form.module.css';
import pageStyles from '@/pages/DashboardPage.module.css';

function DashboardPage() {
  const [mcUsername, setMcUsername] = useState('');
  const [message, setMessage] = useState('');
  const [error, setError] = useState('');

  // TODO: Add current linked account info

  const handleSubmit = async (event) => {
    event.preventDefault();
    setMessage('');
    setError('');

    if (!mcUsername) {
      setError('Please enter your Minecraft username.');
      return;
    }

    try {
      const data = await linkMinecraftUsername(mcUsername);
      setMessage(`${data.message} \n${data.code}`);
      setMcUsername('');
    } catch (err) {
      setError(err.message || 'An unexpected error occurred.');
    }
  };

  return (
    <div className={pageStyles.dashboardContainer}>
      <div className={pageStyles.welcomeHeader}>
        <h1>Dashboard</h1>
        <p>Manage your account settings and Minecraft server access.</p>
      </div>

      <div className={pageStyles.infoCard}>
        <h2>Link Your Minecraft Account</h2>
        <p>
          Enter your Minecraft username below to receive a verifcation code.
          You will need to enter this code in-game to get whitelisted.
        </p>

        <form onSubmit={handleSubmit}>
          <div className={formStyles.formGroup}>
            <label htmlFor="mcUsername" className={formStyles.label}>Minecraft Username:</label>
            <input
              type="text"
              id="mcUsername"
              value={mcUsername}
              onChange={(e) => setMcUsername(e.target.value)}
              className={formStyles.input}
              required
            />
          </div>

          <div className={formStyles.buttonContainer}>
            <button type="submit" className={formStyles.button}>
              Link Account & Get Code
            </button>
          </div>
        </form>

        <div className={formStyles.messageContainer}>
          {message && (
            <div className={formStyles.successMessage} style={{ whiteSpace: 'pre-wrap' }}>
              {message}
            </div>
          )}
          {error && (
            <div className={formStyles.apiErrorBox}>{error}</div>
          )}
        </div>
      </div>
    </div>
  );
}

export default DashboardPage;
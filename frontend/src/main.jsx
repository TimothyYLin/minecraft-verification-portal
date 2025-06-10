import React from 'react';
import { createRoot } from 'react-dom/client';
import { BrowserRouter, Routes, Route } from 'react-router-dom';
import { AuthProvider  } from '@/contexts/AuthProvider';

import App from '@/App.jsx'
import HomePage from '@/pages/HomePage.jsx';
import RegisterPage from '@/pages/RegisterPage.jsx';
import LoginPage from '@/pages/LoginPage.jsx';
import DashboardPage from '@/pages/DashboardPage.jsx';
import EmailVerificationRedirectPage from '@/pages/EmailVerificationRedirectPage.jsx';
import NotFoundPage from '@/pages/NotFoundPage.jsx';
import ProtectedRoute from '@/router/ProtectedRoute';
import PublicRoute from '@/router/PublicRoute';

import '@/index.css';

const container = document.getElementById('root');

const root = createRoot(container);

root.render(
  <React.StrictMode>
    <AuthProvider>
      <BrowserRouter>
        <Routes>
          <Route path="/" element={<App />}>
            <Route index element={<HomePage />} />
            <Route path="login-success" element={<EmailVerificationRedirectPage />} />

            <Route element={<PublicRoute />}>
              <Route path="register" element={<RegisterPage />} />
              <Route path="login" element={<LoginPage />} />
            </Route>

            <Route element={<ProtectedRoute />}>
              <Route path="dashboard" element={<DashboardPage />} />
            </Route>

            <Route path="*" element={<NotFoundPage />} />
          </Route>
        </Routes>
      </BrowserRouter>
    </AuthProvider>
  </React.StrictMode>,
);

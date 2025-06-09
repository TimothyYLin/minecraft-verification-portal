import React from 'react';
import { Outlet, Link, useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import styles from '@/App.module.css'

function App() {
  const { isAuthenticated, user, logout } = useAuth();
  const navigate = useNavigate();

  const handleLogout = async () => {
    await logout();
    navigate('/login');
  }

  return (
    <div className={styles.appContainer}>
      <header className={styles.header}>
        <nav className={styles.nav}>
          <Link to="/" className={styles.navLogo}>Konoha Portal</Link>
          <ul className={styles.navList}>
            {isAuthenticated ? (
              <>
                <li className={styles.userInfo}>Welcome, {user?.email}</li>
                <li><Link to="/dashboard" className={styles.navButton}>Dashboard</Link></li>
                <li>
                  <button onClick={handleLogout} className={`${styles.navButton} ${styles.logoutButton}`}>
                    Logout
                  </button>
                </li>
              </>
            ) : (
              <>
                <li><Link to="/register" className={styles.navButton}>Register</Link></li>
                <li><Link to="/login" className={styles.navButton}>Login</Link></li>
              </>
            )}
          </ul>
        </nav>
      </header>
      <main className={styles.main}>
        <Outlet />
      </main>
      <footer className={styles.footer}>
        <p>&copy; {new Date().getFullYear()} Konoha Minecraft Portal</p>
      </footer>
    </div>    
  );
}

export default App;

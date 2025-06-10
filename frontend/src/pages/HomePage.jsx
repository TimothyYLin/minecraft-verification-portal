import React from 'react';
import { Link, useNavigate } from 'react-router-dom';
import styles from '@/pages/HomePage.module.css';
import formStyles from '@/components/Form/Form.module.css';

function HomePage() {
    const navigate = useNavigate();

    return(
        <div className={styles.heroContainer}>
            <h1 className={styles.title}>Konoha Minecraft Portal</h1>
            <p className={styles.subtitle}>
                The official portal to gain access to the Konoha Minecraft server.
                Register for a new account or log in to link your Minecraft username and get whitelisted.
            </p>
            <div className={styles.ctaContainer}>
                <button
                    onClick={() => navigate('/register')}
                    className={`${formStyles.button} ${styles.ctaButton}`}
                >
                    Get Started
                </button>
            </div>
        </div>
    );
}

export default HomePage;
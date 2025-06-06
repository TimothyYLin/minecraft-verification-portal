import React, { useState } from 'react';
import { registerUser, resendVerificationEmail } from '../services/apiService';
import styles from './RegisterPage.module.css';
import ResendIcon from '../components/common/ResendIcon';

function RegisterPage(){
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');
    const [isApiError, setIsApiError] = useState(false);
    const [showResend, setShowResend] = useState(false);

    const handleResend = async () => {
        setError('');
        setIsApiError(false);
        setShowResend(false);
        setMessage('Sending a new link...');
        try{
            const data = await resendVerificationEmail(email);
            setMessage(data.message);
        }catch(err){
            setMessage('');
            setError(err.message || 'Failed to resend email.');
            setIsApiError(true);
        }
    }

    const handleSubmit = async (event) => {
        event.preventDefault();
        setMessage('');
        setError('');
        setIsApiError(false);

        if(!email || !password){
            setError('Email and password are required.');
            console.log("Error set to: All fields are required.");
            return;
        }

        if(password !== confirmPassword){
            setError('Passwords do not match.');
            console.log("Error set to: Passwords do not match.");
            return;
        }

        try{
            const data = await registerUser(email, password);
            setMessage(data.message);
            setEmail('');
            setPassword('');
            setConfirmPassword('');
        }catch(err){
            setError(err.message || 'Registration failed. Please try again.');
            setIsApiError(true);

            if(err.code === 'ACTIVE_LINK_EXISTS'){
                setShowResend(true);
            }
        }
    };

    return (
        <div className={styles.container}>
        <h1 className={styles.title}>Register New Account</h1>
        
        <form onSubmit={handleSubmit}>
            <div className={styles.formGroup}>
                <label htmlFor="email" className={styles.label}>Email:</label>
                <input
                    type="email"
                    id="email"
                    value={email}
                    onChange={(e) => setEmail(e.target.value)}
                    className={styles.input}
                    required
                    autoComplete="email"
                />
            </div>
            <div className={styles.formGroup}>
                <label htmlFor="password" className={styles.label}>Password:</label>
                <input
                    type="password"
                    id="password"
                    value={password}
                    onChange={(e) => setPassword(e.target.value)}
                    className={styles.input}
                    required
                    autoComplete="new-password"
                />
            </div>
            <div className={styles.formGroup}>
                <label htmlFor="confirmPassword" className={styles.label}>Confirm Password:</label>
                <input
                    type="password"
                    id="confirmPassword"
                    value={confirmPassword}
                    onChange={(e) => setConfirmPassword(e.target.value)}
                    className={styles.input}
                    required
                    autoComplete="new-password" 
                />
            </div>
                <button type="submit" className={styles.button}>
                Register
                </button>
            </form>
            {showResend && (
                <button onClick={handleResend} className={styles.resendButton}>
                    <ResendIcon />
                    Resend verification email
                </button>
            )}
            <div className={styles.messageContainer}>
                {message && (
                    <div className={styles.successMessage}>{message}</div>
                )}

                {error && (
                    isApiError ? (
                        <div className={styles.apiErrorBox}>{error}</div>
                    ) : (
                        <p className={styles.errorText}>{error}</p>
                    )
                )}
            </div>
        </div>
    );
}

export default RegisterPage;
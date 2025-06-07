import React, { useState } from 'react';
import { registerUser, resendVerificationEmail } from '@/services/apiService';

import formStyles from '@/components/Form/Form.module.css';
import pageStyles from '@/pages/RegisterPage.module.css';
import ResendIcon from '@/components/common/ResendIcon';
import PasswordInput from '@/components/Form/PasswordInput';

/**
 * Validates a password against a set of security rules
 * @param {string} password - The password to validate
 * @returns {string[]} Array of error messages for unmet requirements.
 */
const validatePassword = (password) => {
    const errors = [];
    if(password.length < 8){
        errors.push("at least 8 characters long");
    }
    if(!/[A-Z]/.test(password)){
        errors.push("at least one uppercase letter");
    }
    if(!/[a-z]/.test(password)){
        errors.push("at least one lowercase letter");
    }
    if(!/\d/.test(password)){
        errors.push("at least one number");
    }
    if(!/[!@#$%^&*(),.?":{}|<>]/.test(password)){
        errors.push("at least one special character");
    }

    for(let i = 0; i < password.length - 2; ++i){
        const char1 = password.charCodeAt(i);
        const char2 = password.charCodeAt(i + 1);
        const char3 = password.charCodeAt(i + 2);

        if(char1 >= 48 && char1 <= 57){
            if(char2 === char1 + 1 && char3 === char2 + 1){
                errors.push("no sequential numbers (like '123')");
                break;
            }
        }
    }

    return errors;
}

function RegisterPage(){
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [confirmPassword, setConfirmPassword] = useState('');
    const [message, setMessage] = useState('');
    const [error, setError] = useState('');
    const [isApiError, setIsApiError] = useState(false);
    const [showResend, setShowResend] = useState(false);

    const handleResend = async () => {
        setError(null);
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
        setError(null);
        setIsApiError(false);

        if(!email || !password || !confirmPassword){
            setError('All fields are required.');
            console.log("Error set to: All fields are required.");
            return;
        }

        if(password !== confirmPassword){
            setError('Passwords do not match.');
            console.log("Error set to: Passwords do not match.");
            return;
        }

        const passwordErrors = validatePassword(password);
        if(passwordErrors.length > 0){
            setError(passwordErrors);
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
        <div className={formStyles.formContainer}>
            <h1 className={formStyles.title}>Register</h1>

            <form onSubmit={handleSubmit}>
                <div className={formStyles.formGroup}>
                    <label htmlFor="email" className={formStyles.label}>Email:</label>
                    <input
                        type="email"
                        id="email"
                        value={email}
                        onChange={(e) => setEmail(e.target.value)}
                        className={formStyles.input}
                        required
                        autoComplete="email"
                    />
                </div>
                <div className={formStyles.formGroup}>
                    <label htmlFor="password" className={formStyles.label}>Password:</label>
                    <PasswordInput
                        id="password"
                        value={password}
                        onChange={(e) => setPassword(e.target.value)}
                        autoComplete="new-password"
                    />
                </div>
                <div className={formStyles.formGroup}>
                    <label htmlFor="confirmPassword" className={formStyles.label}>Confirm Password:</label>
                    <input
                        type="password"
                        id="confirmPassword"
                        value={confirmPassword}
                        onChange={(e) => setConfirmPassword(e.target.value)}
                        className={formStyles.input}
                        required
                        autoComplete="new-password" 
                    />
                </div>
                <div className={formStyles.buttonContainer}>
                    <button type="submit" className={formStyles.button}>
                    Register
                    </button>
                </div>
            </form>
            {showResend && (
                <div className={formStyles.buttonContainer}>
                    <button onClick={handleResend} className={`${formStyles.button} ${formStyles.resendButton}`}>
                        <ResendIcon />
                        Resend verification email
                    </button>
                </div>
            )}
            <div className={formStyles.messageContainer}>
                {message && (
                    <div className={formStyles.successMessage}>{message}</div>
                )}

                {error && (
                    isApiError ? (
                        <div className={formStyles.apiErrorBox}>{error}</div>
                    ) : (
                        <div className={pageStyles.validationErrorBox}>
                            {Array.isArray(error) ? ( 
                                <>    
                                    <p className={pageStyles.listHeading}>Password must contain:</p>
                                    <ul className={pageStyles.validationErrorList}>
                                        {error.map((err, index) => (
                                            <li key={index}>{err}</li>
                                        ))}
                                    </ul>
                                </>
                        ) : (
                            <p className={pageStyles.singleErrorText}>{error}</p>
                        )}
                        </div>
                    )
                )}
            </div>
        </div>
    );
}

export default RegisterPage;
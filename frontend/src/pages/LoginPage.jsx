import React, {useState} from 'react';
import { useNavigate, Link } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';
import { loginUser, resendVerificationEmail } from '@/services/apiService';

import formStyles from '@/components/Form/Form.module.css';
import ResendIcon from '@/components/common/ResendIcon';
import PasswordInput from '@/components/Form/PasswordInput';

function LoginPage(){
    const { login } = useAuth();
    const [email, setEmail] = useState('');
    const [password, setPassword] = useState('');
    const [error, setError] = useState('');
    const [message, setMessage] = useState('')
    const [isApiError, setIsApiError] = useState(false);
    const [showResend, setShowResend] = useState(false);

    const navigate = useNavigate();

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
    };

    const handleSubmit = async (event) => {
        event.preventDefault();
        setError('');
        setMessage('');
        setIsApiError(false);
        setShowResend(false);

        try{
            const data = await loginUser(email, password);
            login(data.token);
            navigate('/dashboard');
        }catch(err){
            setError(err.message || 'An unexpected error occured.');
            if(err.code === 'EMAIL_NOT_VERIFIED'){
                setShowResend(true);
            }            

            setIsApiError(true);
        }
    };

    return(
        <div className={formStyles.formContainer}>
            <h1 className={formStyles.title}>Login</h1>
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
                <div className={formStyles.buttonContainer}>
                    <button type="submit" className={formStyles.button}>Login</button>
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
                {error && isApiError && (
                    <div className={formStyles.apiErrorBox}>{error}</div>
                )}
            </div>
            <p className={formStyles.bottomLink}>
                Don't have an account? <Link to="/register" className={formStyles.link}>Register here</Link>
            </p>
        </div>
    );
}

export default LoginPage;
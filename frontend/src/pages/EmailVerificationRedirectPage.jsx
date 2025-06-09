import React, { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';
import { useAuth } from '@/hooks/useAuth';

function EmailVerificationRedirectPage(){
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();
    const { login } = useAuth();

    useEffect(() => {
        const token = searchParams.get('token');
        if(token){
            console.log('Captured token:', token);
            login(token);
            navigate('/dashboard', { replace: true });
        }else{
            console.error('No token found in the URL.');
            navigate('/login', { replace: true });
        }
    }, [searchParams, navigate, login]);

    return (
        <div style={{ padding: '40px', textAlign: 'center', color: 'white' }}>
            <h1>Verifying your email...</h1>
            <p>Please wait while we log you in.</p>
        </div>
    );
}

export default EmailVerificationRedirectPage;
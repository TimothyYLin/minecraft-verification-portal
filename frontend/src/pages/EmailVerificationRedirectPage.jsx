import React, { useEffect } from 'react';
import { useSearchParams, useNavigate } from 'react-router-dom';

function EmailVerificationRedirectPage(){
    const [searchParams] = useSearchParams();
    const navigate = useNavigate();

    useEffect(() => {
        const token = searchParams.get('token');
        if(token){
            console.log('Captured token:', token);
            localStorage.setItem('authToken', token);
            navigate('/dashboard');
        }else{
            console.error('No token found in the URL.');
            navigate('/login');
        }
    }, [searchParams, navigate]);

    return (
        <div>
            <h1>Verifying your email...</h1>
            <p>Please wait while we log you in.</p>
        </div>
    );
}

export default EmailVerificationRedirectPage
import React, { useState, useEffect, useCallback } from 'react';
import { linkMinecraftUsername, getAccountStatus } from '@/services/apiService';

import formStyles from '@/components/Form/Form.module.css';
import pageStyles from '@/pages/DashboardPage.module.css';

function Countdown({ expiryTimestamp, onExpire }) {
	const calculateTimeLeft = () => {
		const difference = +new Date(expiryTimestamp) - +new Date();
		return difference > 0 ? difference : 0;
	}

	const [timeLeft, setTimeLeft] = useState(calculateTimeLeft());

	useEffect(() => {
		if (timeLeft <= 0) {
			onExpire();
			return;
		}
		const timer = setTimeout(() => setTimeLeft(calculateTimeLeft()), 1000);
		return () => clearTimeout(timer);
	}, [timeLeft, onExpire]);

	const minutes = String(Math.floor((timeLeft / 1000 / 60) % 60)).padStart(2, '0');
	const seconds = String(Math.floor((timeLeft / 1000) % 60)).padStart(2, '0');

	return <span>(Expires in {minutes}:{seconds})</span>;
}

function DashboardPage() {
	const [mcUsername, setMcUsername] = useState('');
	const [error, setError] = useState('');

	const [accountStatus, setAccountStatus] = useState(null);
	const [isLoading, setIsLoading] = useState(true);
    const [isSubmitting, setIsSubmitting] = useState(false);

    const fetchAccountStatus = useCallback(async () => {
        try {
            const status = await getAccountStatus();
            setAccountStatus(status);
        } catch (err) {
            setError(err.message || 'Could not load account status.');
        }
    }, []);

    useEffect(() => {
        const getStatus = async () => {
            await fetchAccountStatus();
            setIsLoading(false);
        };
        getStatus();
    }, [fetchAccountStatus]);

	const handleSubmit = async (event) => {
		event.preventDefault();
		setError('');

		if (!mcUsername) {
			setError('Please enter your Minecraft username.');
			return;
		}

        setIsSubmitting(true);
		try{
			await linkMinecraftUsername(mcUsername);
			await fetchAccountStatus();
            setAccountStatus(newStatus);
			setMcUsername('');
		}catch(err){
			setError(err.message || 'An unexpected error occurred.');
		}finally{
            setIsSubmitting(false);
        }
	};

    if(isLoading){
        return <div>Loading dashboard...</div>;
    }

    const renderStatus = () => {
        if(!accountStatus?.mc_username){
            return null;
        }
        if(accountStatus.mc_verified){
            return (
                <div className={pageStyles.statusDisplay}>
                    <h3>Your Linked Minecraft Account</h3>
                    <p>Username: <strong>{accountStatus.mc_username}</strong></p>
                    <p className={pageStyles.verifiedStatus}>Status: Verified</p>
                </div>
            );
        }
        if(accountStatus.active_code){
            return (
                <div className={pageStyles.statusDisplay}>
                    <h3>Your Verification Code</h3>
                    <p>Enter this code in game to verify <strong>{accountStatus.mc_username}</strong>:</p>
                    <div className={pageStyles.code}>{accountStatus.active_code}</div>
                    <p className={pageStyles.expires}>
                        <Countdown
                            expiryTimestamp={accountStatus.code_expires_at}
                            onExpire={fetchAccountStatus}
                        />
                    </p>
                </div>
            );
        }

        return (
            <div className={pageStyles.statusDisplay}>
                <p>Your previous verification code for <strong>{accountStatus.mc_username}</strong> has expired.</p>
                <p>Please use the form below to generate a new code.</p>
            </div>
        );
    };

	return (
		<div className={pageStyles.dashboardContainer}>
			<div className={pageStyles.welcomeHeader}>
				<h1>Dashboard</h1>
				<p>Manage your account settings and Minecraft server access.</p>
			</div>

            {renderStatus()}

            {!accountStatus?.active_code && (
                <div className={pageStyles.infoCard}>
                    <h2>
                        {accountStatus?.mc_username ? 
                            'Link a Different or New Minecraft Account' :
                            'Link Your Minecraft Account'}
                    </h2>

                    <form onSubmit={handleSubmit}>
                        <div className={formStyles.formGroup}>
                            <label htmlFor="mcUsername" className={formStyles.label}>Minecraft Username:</label>
                            <input
                                type="text"
                                id="mcUsername"
                                placeholder={accountStatus?.mc_username || 'Enter username'}
                                value={mcUsername}
                                onChange={(e) => setMcUsername(e.target.value)}
                                className={formStyles.input}
                                required
                            />
                        </div>

                        <div className={formStyles.buttonContainer}>
                            <button type="submit" className={formStyles.button}>
                                {isSubmitting
                                    ? 'Submitting...'
                                    : (accountStatus?.mc_username ?
                                        'Generate New Code' :
                                        'Get Verification Code')
                                }
                            </button>
                        </div>
                    </form>

                    {error && (
                        <div className={formStyles.messageContainer}>
                            <div className={formStyles.apiErrorBox}>{error}</div>
                        </div>
                    )}
                </div>
            )}
		</div>
	);
}

export default DashboardPage;
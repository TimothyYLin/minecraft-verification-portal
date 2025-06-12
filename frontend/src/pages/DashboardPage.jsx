import React, { useState, useEffect, useCallback, useRef } from 'react';
import { linkMinecraftUsername, getAccountStatus } from '@/services/apiService';

import formStyles from '@/components/Form/Form.module.css';
import pageStyles from '@/pages/DashboardPage.module.css';
import AccountList from '@/components/Dashboard/AccountList';

function Countdown({ expiryTimestamp, onExpire }) {
	const calculateTimeLeft = useCallback(() => {
		const difference = +new Date(expiryTimestamp) - +new Date();
    	return difference > 0 ? difference : 0;
	}, [expiryTimestamp]);

	const [timeLeft, setTimeLeft] = useState(calculateTimeLeft());

	useEffect(() => {
		if (timeLeft <= 0) {
			onExpire();
			return;
		}
		const timer = setTimeout(() => setTimeLeft(calculateTimeLeft()), 1000);
		return () => clearTimeout(timer);
	}, [timeLeft, onExpire, calculateTimeLeft]);

	const minutes = String(Math.floor((timeLeft / 1000 / 60) % 60)).padStart(2, '0');
	const seconds = String(Math.floor((timeLeft / 1000) % 60)).padStart(2, '0');

	return <span>(Expires in {minutes}:{seconds})</span>;
}

function DashboardPage() {
	const [mcUsername, setMcUsername] = useState('');
	const [error, setError] = useState('');
    const [infoMessage, setInfoMessage] = useState('');
	const [accountStatus, setAccountStatus] = useState(null);
	const [isLoading, setIsLoading] = useState(true);
    const [isSubmitting, setIsSubmitting] = useState(false);
    const [recentlyVerifiedAccount, setRecentlyVerifiedAccount] = useState(null);
    const pollingIntervalRef = useRef(null);

    const fetchAccountStatus = useCallback(async () => {
        try {
            const status = await getAccountStatus();

            if(pollingIntervalRef.current && accountStatus?.active_verification && !status.active_verification){
                const verifiedAccount = status.linked_accounts.find(
                    acc => acc.mc_username === accountStatus.active_verification.mc_username && acc.is_verified
                );
                if(verifiedAccount){
                    setRecentlyVerifiedAccount(verifiedAccount.mc_username);
                    clearInterval(pollingIntervalRef.current);
                    pollingIntervalRef.current = null;
                }
            }

            setAccountStatus(status);
        } catch (err) {
            setError(err.message || 'Could not load account status.');
        }
    }, [accountStatus]);

    useEffect(() => {
        const initialLoad = async () => {
            setIsLoading(true);
            await fetchAccountStatus();
            setIsLoading(false);
        };
        initialLoad();
    }, []);

    useEffect(() => {
        const cleanup = () => {
            if(pollingIntervalRef.current){
                clearInterval(pollingIntervalRef.current);
                pollingIntervalRef.current = null;
            }
        };

        if(accountStatus?.active_verification){
            if(!pollingIntervalRef.current){
                pollingIntervalRef.current = setInterval(fetchAccountStatus, 5000);
            }
        }else{
            cleanup();
        }

        return cleanup;
    }, [accountStatus?.active_verification, fetchAccountStatus]);

    const lastNotVerifiedAcc = accountStatus?.linked_accounts?.find(acc => !acc.is_verified);

	const handleSubmit = async (event) => {
		event.preventDefault();
		setError('');
        setInfoMessage('');
        setRecentlyVerifiedAccount(null);

        let usernameToSubmit = mcUsername.trim();
        if(!usernameToSubmit && lastNotVerifiedAcc?.mc_username){
            usernameToSubmit = lastNotVerifiedAcc.mc_username;
        }

		if (!usernameToSubmit) {
			setError('Please enter your Minecraft username.');
			return;
		}

        setIsSubmitting(true);
		try{
			const response = await linkMinecraftUsername(usernameToSubmit);
            await fetchAccountStatus();

            if(response.code === 'ALREADY_VERIFIED'){
                setInfoMessage(response.message);
            }

            setMcUsername('');
		}catch(err){
			setError(err.message || 'An unexpected error occurred.');
            setMcUsername('');
		}finally{
            setIsSubmitting(false);
        }
	};

    const handleKeyDown = (e) => {
        if(e.key === 'Enter'){
            if(e.currentTarget.value.trim() === '' && e.currentTarget.placeholder && e.currentTarget.placeholder !== 'Enter username'){
                setMcUsername(e.currentTarget.placeholder);
                e.preventDefault();
            }
        }
    }

    if(isLoading){
        return <div>Loading dashboard...</div>;
    }

    const renderStatusMessages = () => {
        if(recentlyVerifiedAccount){
            return (
                <div className={pageStyles.successDisplay}>
                    <p><strong>Successfully verified {recentlyVerifiedAccount}!</strong></p>
                </div>
            )
        }

        if(accountStatus?.active_verification){
            return (
                <div className={pageStyles.statusDisplay}>
                    <h3>Your Verification Code</h3>
                    <p>Enter this code in game to verify <strong>{accountStatus.active_verification.mc_username}</strong>:</p>
                    <div className={pageStyles.code}>{accountStatus.active_verification.code}</div>
                    <p className={pageStyles.expires}>
                        <Countdown
                            expiryTimestamp={accountStatus.active_verification.expires_at}
                            onExpire={fetchAccountStatus}
                        />
                    </p>
                </div>
            )
        }

        if(lastNotVerifiedAcc && !isSubmitting && !infoMessage && !error){
            return (
                <div className={pageStyles.statusDisplay}>
                    <p>Your previous verification code for <strong>{accountStatus?.linked_accounts[0]?.mc_username}</strong> has expired.</p>
                    <p>Please use the form below to generate a new code.</p>
                </div>
            );
        }

        return null;
    };

	return (
		<div className={pageStyles.dashboardContainer}>
			<div className={pageStyles.welcomeHeader}>
				<h1>Dashboard</h1>
				<p>Manage your account settings and Minecraft server access.</p>
			</div>

            {renderStatusMessages()}

            <AccountList accounts={accountStatus?.linked_accounts}/>

            {!accountStatus?.active_verification && (
                <div className={pageStyles.infoCard}>
                    <h2>
                        {accountStatus?.linked_accounts?.length > 0 ? 
                            'Link a Different Minecraft Account' :
                            'Link Your Minecraft Account'}
                    </h2>

                    <form onSubmit={handleSubmit}>
                        <div className={formStyles.formGroup}>
                            <label htmlFor="mcUsername" className={formStyles.label}>Minecraft Username:</label>
                            <input
                                type="text"
                                id="mcUsername"
                                placeholder={lastNotVerifiedAcc?.mc_username || 'Enter username'}
                                value={mcUsername}
                                onChange={(e) => setMcUsername(e.target.value)}
                                onKeyDown={handleKeyDown}
                                className={formStyles.input}
                            />
                            {lastNotVerifiedAcc && (
                                <p className={formStyles.helperText}>
                                    This is your most recently linked and unverified account.
                                    Click the button to get a new verification code for it, or type a different name.
                                </p>
                            )}
                        </div>

                        <div className={formStyles.buttonContainer}>
                            <button type="submit" className={formStyles.button}>
                                {isSubmitting
                                    ? 'Submitting...'
                                    : 'Get Verification Code'
                                }
                            </button>
                        </div>
                    </form>
                    <div className={formStyles.messageContainer}>
                        {infoMessage && (<div className={formStyles.apiInfoBox}>{infoMessage}</div>)}
                        {error && (<div className={formStyles.apiErrorBox}>{error}</div>)}
                    </div>
                </div>
            )}
		</div>
	);
}

export default DashboardPage;
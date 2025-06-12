import React from 'react';
import styles from '@/components/Dashboard/AccountList.module.css';

function AccountList({ accounts }){
    if(!accounts || accounts.length === 0){
        return null;
    }

    return (
        <div className={styles.listContainer}>
            <h2> Your Linked Minecraft Accounts</h2>
            <ul className = {styles.AccountList}>
                {accounts.map(account => (
                    <li key={account.id} className={styles.accountItem}>
                        <span className={styles.username}>{account.mc_username}</span>
                        <span className={`${styles.status} ${account.is_verified ? styles.verified : styles.notVerified}`}>
                            {account.is_verified ? 'Verified' : 'Not Verified'}
                        </span>
                    </li>
                ))}
            </ul>
        </div>
    )
}

export default AccountList;
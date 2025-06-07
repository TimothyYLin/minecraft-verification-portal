import React, { useState } from 'react';

import formStyles from '@/components/Form/Form.module.css';
import EyeIcon from '@/components/common/EyeIcon';
import EyeOffIcon from '@/components/common/EyeOffIcon';

const wrapperStyle = {
    position: 'relative',
    display: 'flex',
    alignItems: 'center',
};

function PasswordInput({ value, onChange, id, autoComplete }) {
    const [isShown, setIsShown] = useState(false);

    const toggleVisibility = () => {
        setIsShown(current => !current);
    };

    const toggleButtonStyle = {
        position: 'absolute',
        right: '10px',
        top: '50%',
        transform: 'translateY(-50%)',
        background: 'transparent',
        border: 'none',
        cursor: 'pointer',
        color: isShown ? '#e0e0e0' : '#888',
        padding: '5px',
        display: 'flex',
        alignItems: 'center',
    };

    return (
        <div style={wrapperStyle}>
            <input
                type={isShown ? 'text' : 'password'}
                id={id}
                value={value}
                onChange={onChange}
                className={formStyles.input}
                required
                autoComplete={autoComplete}
            />
            <button type="button" onClick={toggleVisibility} style={toggleButtonStyle} aria-label="Toggle password visibility">
                {isShown ?  <EyeIcon /> : <EyeOffIcon /> }
            </button>
        </div>
    );
}

export default PasswordInput;
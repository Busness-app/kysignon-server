import React, { useState } from 'react';
import { THEMES, THEME_NAMES, ThemeName, applyTheme, isLight, saveTheme, storedTheme } from '../theme';

export const Appearance: React.FC = () => {
  const [current, setCurrent] = useState<ThemeName>(storedTheme);

  const choose = (name: ThemeName) => {
    applyTheme(name);
    saveTheme(name);
    setCurrent(name);
  };

  return (
    <div>
      <div className="page-header">
        <h1 className="page-title">Appearance</h1>
      </div>
      <ul className="theme-grid">
        {THEME_NAMES.map((name) => {
          const t = THEMES[name];
          return (
            <li key={name}>
              <button type="button" className="swatch" aria-pressed={name === current} onClick={() => choose(name)}>
                <span className="swatch-preview" style={{ background: `linear-gradient(90deg, ${t.sidebarStart} 30%, ${t.bg} 30%)` }}>
                  <i style={{ background: t.accent }} />
                  <i style={{ background: t.inkStrong }} />
                </span>
                <span>{name}</span>
                <small>{isLight(t.bg) ? 'Light' : 'Dark'}</small>
              </button>
            </li>
          );
        })}
      </ul>
    </div>
  );
};

import React from 'react';
import styles from './styles.module.css';

export default function Footer() {
  return (
    <footer id="site-footer" className={styles.footer}>
      <div className={styles.container}>
        <div className={styles.footerInner}>

          <div className={styles.footerCol}>
            <div className={styles.footerBrand}>
              <img src="/img/logo-footer.png" alt="GoRelay" style={{height:'54px',width:'auto',opacity:'0.9'}} />
            </div>
            
            <p className={styles.footerNote}>Independent project by IT and More Systems.<br/>SMP compatibility maintained for SimpleX Chat interoperability.</p>
          </div>

          <div className={styles.footerCol}>
            <h4>Project</h4>
            <a href="https://github.com/saschadaemgen/GoRelay" target="_blank" rel="noopener noreferrer">GitHub</a>
            <a href="https://simplego.dev" target="_blank" rel="noopener noreferrer">SimpleGo</a>
            <a href="https://simplego.dev/network" target="_blank" rel="noopener noreferrer">Network</a>
            <a href="https://x.com/simplegodev" target="_blank" rel="noopener noreferrer">X / Twitter</a>
          </div>

          <div className={styles.footerCol}>
            <h4>Legal</h4>
            <a href="https://simplego.dev/legal/tos">Terms of Service</a>
            <a href="https://simplego.dev/legal/privacy">Privacy Policy</a>
            <a href="https://simplego.dev/legal/disclaimer">Disclaimer</a>
            <a href="/imprint">Imprint</a>
          </div>

          <div className={styles.footerCol}>
            <h4>Trust and Compliance</h4>
            <a href="https://simplego.dev/legal/aup">Acceptable Use</a>
            <a href="https://simplego.dev/legal/law-enforcement">Law Enforcement</a>
            <a href="https://simplego.dev/legal/transparency">Transparency Report</a>
          </div>

          <div className={styles.footerCol}>
            <h4>Company</h4>
            <a href="https://simplego.dev/contact">Partnership</a>
            <a href="https://simplego.dev/ost">Soundtrack</a>
            <a href="#">Kickstarter <span className={styles.comingSoon}>SOON</span></a>
            <a href="mailto:contact@simplego.dev">Contact</a>
          </div>

        </div>
      </div>

      <div className={styles.footerBottom}>
        <div className={styles.container}>
          <div className={styles.footerBottomInner}>
            <span>&copy; 2026 GoRelay.dev - IT and More Systems</span>
            <span>
              Software: <a href="https://github.com/saschadaemgen/GoRelay/blob/main/LICENSE" target="_blank" rel="noopener noreferrer">AGPL-3.0</a>
            </span>
          </div>
        </div>
      </div>
    </footer>
  );
}

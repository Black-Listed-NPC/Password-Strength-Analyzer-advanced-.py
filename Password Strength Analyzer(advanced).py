import re
import string
import secrets
import hashlib
import json
import os
from datetime import datetime
from typing import List, Tuple, Dict

class PasswordStrengthAnalyzer:
    """Analyzes password strength and provides security recommendations."""
    
    def __init__(self, history_file: str = "password_history.json"):
        self.history_file = history_file
        self.common_passwords = self._load_common_passwords()
        
    def _load_common_passwords(self) -> set:
        """Load common passwords to check against."""
        # Top 100 most common passwords
        common = {
            'password', '123456', '123456789', 'qwerty', 'abc123',
            'password1', '12345678', '111111', '1234567', 'sunshine',
            'qwerty123', 'password123', 'welcome', 'admin', 'login',
            'passw0rd', 'master', 'hello', 'freedom', 'whatever',
            'football', 'monkey', 'dragon', 'letmein', 'trustno1',
            'shadow', 'michael', 'jennifer', 'jordan', 'hunter',
            '1234567890', 'starwars', 'password!', 'iloveyou', 'batman'
        }
        return common
    
    def analyze_password(self, password: str) -> Dict:
        """
        Comprehensive password analysis.
        
        Returns:
            Dictionary containing strength score, feedback, and recommendations.
        """
        analysis = {
            'password_length': len(password),
            'score': 0,
            'max_score': 100,
            'strength_level': '',
            'checks': {},
            'feedback': [],
            'recommendations': []
        }
        
        # Length check
        length_score, length_feedback = self._check_length(password)
        analysis['score'] += length_score
        analysis['checks']['length'] = length_score
        analysis['feedback'].extend(length_feedback)
        
        # Complexity checks
        complexity_score, complexity_feedback = self._check_complexity(password)
        analysis['score'] += complexity_score
        analysis['checks']['complexity'] = complexity_score
        analysis['feedback'].extend(complexity_feedback)
        
        # Common password check
        common_score, common_feedback = self._check_common_passwords(password)
        analysis['score'] += common_score
        analysis['checks']['common'] = common_score
        analysis['feedback'].extend(common_feedback)
        
        # Pattern check
        pattern_score, pattern_feedback = self._check_patterns(password)
        analysis['score'] += pattern_score
        analysis['checks']['patterns'] = pattern_score
        analysis['feedback'].extend(pattern_feedback)
        
        # Uniqueness check (against history)
        unique_score, unique_feedback = self._check_uniqueness(password)
        analysis['score'] += unique_score
        analysis['checks']['uniqueness'] = unique_score
        analysis['feedback'].extend(unique_feedback)
        
        # Determine strength level
        analysis['strength_level'] = self._get_strength_level(analysis['score'])
        
        # Generate recommendations
        analysis['recommendations'] = self._generate_recommendations(analysis)
        
        return analysis
    
    def _check_length(self, password: str) -> Tuple[int, List[str]]:
        """Check password length (max 25 points)."""
        length = len(password)
        feedback = []
        
        if length < 6:
            score = 0
            feedback.append("❌ Password is too short (less than 6 characters)")
        elif length < 8:
            score = 10
            feedback.append("⚠️  Password is weak (6-7 characters)")
        elif length < 12:
            score = 15
            feedback.append("✓ Acceptable length (8-11 characters)")
        elif length < 16:
            score = 20
            feedback.append("✓✓ Good length (12-15 characters)")
        else:
            score = 25
            feedback.append("✓✓✓ Excellent length (16+ characters)")
        
        return score, feedback
    
    def _check_complexity(self, password: str) -> Tuple[int, List[str]]:
        """Check password complexity (max 35 points)."""
        score = 0
        feedback = []
        
        # Check for lowercase letters
        if re.search(r'[a-z]', password):
            score += 5
            feedback.append("✓ Contains lowercase letters")
        else:
            feedback.append("❌ Missing lowercase letters")
        
        # Check for uppercase letters
        if re.search(r'[A-Z]', password):
            score += 5
            feedback.append("✓ Contains uppercase letters")
        else:
            feedback.append("❌ Missing uppercase letters")
        
        # Check for digits
        if re.search(r'\d', password):
            score += 5
            feedback.append("✓ Contains numbers")
        else:
            feedback.append("❌ Missing numbers")
        
        # Check for special characters
        if re.search(r'[!@#$%^&*()_+\-=\[\]{};:\'",.<>?/\\|`~]', password):
            score += 10
            feedback.append("✓✓ Contains special characters")
        else:
            feedback.append("❌ Missing special characters")
        
        # Check character variety
        unique_chars = len(set(password))
        if unique_chars >= len(password) * 0.7:
            score += 10
            feedback.append("✓✓ Good character variety")
        elif unique_chars >= len(password) * 0.5:
            score += 5
            feedback.append("✓ Moderate character variety")
        else:
            feedback.append("⚠️  Low character variety (repeated characters)")
        
        return score, feedback
    
    def _check_common_passwords(self, password: str) -> Tuple[int, List[str]]:
        """Check if password is in common passwords list (max 15 points)."""
        feedback = []
        
        if password.lower() in self.common_passwords:
            score = 0
            feedback.append("❌ This is a commonly used password - very unsafe!")
        else:
            score = 15
            feedback.append("✓✓ Not in common passwords list")
        
        return score, feedback
    
    def _check_patterns(self, password: str) -> Tuple[int, List[str]]:
        """Check for predictable patterns (max 15 points)."""
        score = 15
        feedback = []
        
        # Check for sequential numbers
        if re.search(r'(012|123|234|345|456|567|678|789|890)', password):
            score -= 5
            feedback.append("⚠️  Contains sequential numbers")
        
        # Check for sequential letters
        if re.search(r'(abc|bcd|cde|def|efg|fgh|ghi|hij|ijk|jkl|klm|lmn|mno|nop|opq|pqr|qrs|rst|stu|tuv|uvw|vwx|wxy|xyz)', password.lower()):
            score -= 5
            feedback.append("⚠️  Contains sequential letters")
        
        # Check for keyboard patterns
        keyboard_patterns = ['qwerty', 'asdf', 'zxcv', '1qaz', '2wsx']
        if any(pattern in password.lower() for pattern in keyboard_patterns):
            score -= 5
            feedback.append("⚠️  Contains keyboard pattern")
        
        # Check for repeated characters
        if re.search(r'(.)\1{2,}', password):
            score -= 5
            feedback.append("⚠️  Contains repeated characters")
        
        if score == 15:
            feedback.append("✓✓ No predictable patterns detected")
        
        return max(0, score), feedback
    
    def _check_uniqueness(self, password: str) -> Tuple[int, List[str]]:
        """Check if password was used before (max 10 points)."""
        feedback = []
        
        password_hash = self._hash_password(password)
        
        if self._is_password_reused(password_hash):
            score = 0
            feedback.append("❌ This password was used before - choose a unique one!")
        else:
            score = 10
            feedback.append("✓✓ Password is unique (not used before)")
        
        return score, feedback
    
    def _hash_password(self, password: str) -> str:
        """Hash password using SHA-256."""
        return hashlib.sha256(password.encode()).hexdigest()
    
    def _is_password_reused(self, password_hash: str) -> bool:
        """Check if password hash exists in history."""
        if not os.path.exists(self.history_file):
            return False
        
        try:
            with open(self.history_file, 'r') as f:
                history = json.load(f)
                return password_hash in [entry['hash'] for entry in history]
        except:
            return False
    
    def save_password_to_history(self, password: str) -> None:
        """Save password hash to history."""
        password_hash = self._hash_password(password)
        
        history = []
        if os.path.exists(self.history_file):
            try:
                with open(self.history_file, 'r') as f:
                    history = json.load(f)
            except:
                history = []
        
        # Add new entry
        history.append({
            'hash': password_hash,
            'timestamp': datetime.now().isoformat(),
            'length': len(password)
        })
        
        # Keep only last 50 passwords
        history = history[-50:]
        
        with open(self.history_file, 'w') as f:
            json.dump(history, f, indent=2)
    
    def _get_strength_level(self, score: int) -> str:
        """Determine password strength level."""
        if score < 30:
            return "Very Weak"
        elif score < 50:
            return "Weak"
        elif score < 70:
            return "Moderate"
        elif score < 85:
            return "Strong"
        else:
            return "Very Strong"
    
    def _generate_recommendations(self, analysis: Dict) -> List[str]:
        """Generate specific recommendations based on analysis."""
        recommendations = []
        
        if analysis['password_length'] < 12:
            recommendations.append("Increase password length to at least 12 characters")
        
        if analysis['checks']['complexity'] < 25:
            recommendations.append("Use a mix of uppercase, lowercase, numbers, and special characters")
        
        if analysis['checks']['common'] == 0:
            recommendations.append("Avoid common passwords - choose something unique")
        
        if analysis['checks']['patterns'] < 15:
            recommendations.append("Avoid predictable patterns and sequences")
        
        if analysis['checks']['uniqueness'] == 0:
            recommendations.append("Use a different password than previous ones")
        
        if not recommendations:
            recommendations.append("Your password meets security requirements!")
        
        return recommendations
    
    def generate_strong_password(self, length: int = 16, 
                                include_symbols: bool = True) -> str:
        """Generate a cryptographically strong random password."""
        characters = string.ascii_letters + string.digits
        if include_symbols:
            characters += string.punctuation
        
        # Ensure password contains at least one of each type
        password = [
            secrets.choice(string.ascii_lowercase),
            secrets.choice(string.ascii_uppercase),
            secrets.choice(string.digits),
        ]
        
        if include_symbols:
            password.append(secrets.choice(string.punctuation))
        
        # Fill the rest with random characters
        password += [secrets.choice(characters) for _ in range(length - len(password))]
        
        # Shuffle to avoid predictable pattern
        secrets.SystemRandom().shuffle(password)
        
        return ''.join(password)
    
    def generate_passphrase(self, word_count: int = 4) -> str:
        """Generate a memorable passphrase."""
        # Simple word list for demonstration
        words = [
            'correct', 'horse', 'battery', 'staple', 'purple', 'monkey',
            'dishwasher', 'elephant', 'mountain', 'river', 'sunset',
            'keyboard', 'window', 'galaxy', 'thunder', 'rainbow',
            'penguin', 'wizard', 'dragon', 'phoenix', 'crystal',
            'ocean', 'forest', 'desert', 'tundra', 'meadow'
        ]
        
        selected_words = [secrets.choice(words) for _ in range(word_count)]
        
        # Add a number and symbol for extra security
        number = str(secrets.randbelow(100))
        symbol = secrets.choice('!@#$%^&*')
        
        return '-'.join(selected_words) + number + symbol


def print_analysis(analysis: Dict) -> None:
    """Pretty print password analysis."""
    print("\n" + "="*60)
    print("PASSWORD STRENGTH ANALYSIS")
    print("="*60)
    
    # Score and strength
    print(f"\nOverall Score: {analysis['score']}/{analysis['max_score']}")
    print(f"Strength Level: {analysis['strength_level']}")
    
    # Visual strength bar
    bar_length = 40
    filled_length = int(bar_length * analysis['score'] / analysis['max_score'])
    bar = '█' * filled_length + '░' * (bar_length - filled_length)
    print(f"[{bar}]")
    
    # Detailed feedback
    print("\n" + "-"*60)
    print("DETAILED FEEDBACK:")
    print("-"*60)
    for item in analysis['feedback']:
        print(f"  {item}")
    
    # Recommendations
    if analysis['recommendations']:
        print("\n" + "-"*60)
        print("RECOMMENDATIONS:")
        print("-"*60)
        for i, rec in enumerate(analysis['recommendations'], 1):
            print(f"  {i}. {rec}")
    
    print("="*60 + "\n")


def main():
    """Main program loop."""
    analyzer = PasswordStrengthAnalyzer()
    
    print("╔════════════════════════════════════════════════════════╗")
    print("║       PASSWORD STRENGTH ANALYZER                      ║")
    print("║       Learn about password security!                  ║")
    print("╚════════════════════════════════════════════════════════╝")
    
    while True:
        print("\n┌────────────────────────────────────────────────────┐")
        print("│ OPTIONS:                                           │")
        print("│ 1. Analyze a password                              │")
        print("│ 2. Generate strong random password                 │")
        print("│ 3. Generate memorable passphrase                   │")
        print("│ 4. View password tips                              │")
        print("│ 5. Exit                                            │")
        print("└────────────────────────────────────────────────────┘")
        
        choice = input("\nEnter your choice (1-5): ").strip()
        
        if choice == '1':
            print("\n" + "─"*60)
            password = input("Enter password to analyze: ")
            
            if not password:
                print("❌ Password cannot be empty!")
                continue
            
            analysis = analyzer.analyze_password(password)
            print_analysis(analysis)
            
            # Ask if user wants to save to history
            if analysis['score'] >= 70:
                save = input("Save this password to history? (y/n): ").lower()
                if save == 'y':
                    analyzer.save_password_to_history(password)
                    print("✓ Password saved to history")
        
        elif choice == '2':
            print("\n" + "─"*60)
            try:
                length = int(input("Enter desired password length (12-32, default 16): ") or "16")
                length = max(12, min(32, length))
            except ValueError:
                length = 16
            
            symbols = input("Include symbols? (y/n, default y): ").lower() != 'n'
            
            password = analyzer.generate_strong_password(length, symbols)
            print(f"\n✓ Generated password: {password}")
            
            # Analyze generated password
            analysis = analyzer.analyze_password(password)
            print(f"  Strength: {analysis['strength_level']} ({analysis['score']}/100)")
        
        elif choice == '3':
            print("\n" + "─"*60)
            try:
                word_count = int(input("Enter number of words (3-6, default 4): ") or "4")
                word_count = max(3, min(6, word_count))
            except ValueError:
                word_count = 4
            
            passphrase = analyzer.generate_passphrase(word_count)
            print(f"\n✓ Generated passphrase: {passphrase}")
            
            # Analyze generated passphrase
            analysis = analyzer.analyze_password(passphrase)
            print(f"  Strength: {analysis['strength_level']} ({analysis['score']}/100)")
        
        elif choice == '4':
            print("\n" + "="*60)
            print("PASSWORD SECURITY TIPS")
            print("="*60)
            print("""
  1. LENGTH MATTERS:
     • Use at least 12 characters (16+ is better)
     • Longer passwords are exponentially harder to crack
  
  2. COMPLEXITY:
     • Mix uppercase and lowercase letters
     • Include numbers and special characters
     • Use unpredictable combinations
  
  3. AVOID COMMON MISTAKES:
     • Don't use dictionary words
     • Avoid personal information (birthdays, names)
     • Don't use keyboard patterns (qwerty, asdf)
     • Avoid simple substitutions (pa$$w0rd)
  
  4. UNIQUENESS:
     • Use different passwords for different accounts
     • Never reuse old passwords
     • Change passwords periodically
  
  5. BEST PRACTICES:
     • Use a password manager
     • Enable two-factor authentication
     • Consider using passphrases
     • Never share your passwords
  
  6. PASSPHRASE EXAMPLE:
     • "correct-horse-battery-staple" (easier to remember)
     • Add numbers and symbols for extra security
            """)
            print("="*60)
        
        elif choice == '5':
            print("\n👋 Thank you for using Password Strength Analyzer!")
            print("Stay secure! 🔒\n")
            break
        
        else:
            print("\n❌ Invalid choice. Please try again.")


if __name__ == "__main__":
    main()
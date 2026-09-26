import csv
import os
import random

def generate_dataset():
    random.seed(42)

    # 1. NORMAL SAMPLES (Navigation, standard product info, search, standard UI)
    normal_templates = [
        "View Product Details", "Add to Cart", "Buy Now", "Search products...", "Filter by price",
        "Category: Electronics", "Customer Reviews (4.5/5)", "In Stock", "Free Shipping on orders over $50",
        "Home", "About Us", "Contact Us", "Privacy Policy", "Terms of Service", "Help Center",
        "Account Settings", "Log In", "Sign Up", "My Orders", "Wishlist", "Compare Items",
        "Item added to cart", "Quantity: 1", "Select Color: Black", "Select Size: Medium",
        "Estimated Delivery: 3-5 business days", "Order Summary", "Subtotal: $49.99", "Tax: $4.00",
        "Shipping Address", "Payment Method: Credit Card", "Place Order", "Track Package",
        "Returns & Exchanges", "Store Locator", "Subscribe to newsletter for weekly updates",
        "Read our blog", "Follow us on Twitter", "Copyright 2026 All Rights Reserved",
        "FAQ", "Customer Support Available 24/7", "Download User Manual", "Specification Sheet",
        "Standard Shipping Rate applies", "Click to enlarge image", "Product Features",
        "Manufacturer Warranty included", "Secure Checkout SSL Encrypted", "View Cart",
        "Back to top", "Previous page", "Next page", "Page 1 of 5", "Sort by relevance",
        "Sort by price: low to high", "Sort by price: high to low", "New Arrivals", "Best Sellers",
        "Featured Items", "Clear filter", "Apply discount code", "Gift card code", "Redeem points",
        "User Profile", "Change Password", "Email Notifications Preferences", "Save Changes",
        "Cancel Edit", "Download PDF Invoice", "Print Receipt", "Share on Facebook",
        "Share via Email", "Technical Specifications", "Dimensions: 10 x 5 x 2 inches",
        "Weight: 1.2 lbs", "Material: Stainless Steel", "Color Options: Blue, Red, Silver",
        "Compatibility: iOS and Android", "Battery Life: up to 12 hours", "Package includes charger",
        "Search results for headphones", "No items matched your search query", "Showing 1-20 of 100 items",
        "Sign out", "Welcome back, User", "Update Billing Info", "Default Address",
        "Standard Return Policy applies within 30 days", "Need assistance? Chat with us",
        "Cookie Notice: We use essential cookies to ensure web functionality."
    ]

    # Expand normal templates
    normal_samples = []
    normal_modifiers = [
        "", " - Official Store", " (Optional)", " - Learn More", " - Click here", " - Details",
        " | Customer Care", " - Available now", " (Standard Rate)", " [Verified]"
    ]
    for base in normal_templates:
        for mod in normal_modifiers:
            normal_samples.append(base + mod)
    
    # Add more diverse normal variations
    normal_actions = ["View", "Check", "Open", "Browse", "Select", "Download", "Print", "Read", "Explore"]
    normal_targets = ["documentation", "specifications", "user guide", "catalog", "menu", "pricing table", "privacy statement", "terms of use", "shipping policy", "refund policy", "contact form", "store hours", "branch list", "release notes"]
    for act in normal_actions:
        for tgt in normal_targets:
            normal_samples.append(f"{act} {tgt}")

    # 2. URGENCY SAMPLES
    urgency_templates = [
        "Hurry! Offer expires in {m}:{s} minutes!",
        "Sale ends in {m} minutes!",
        "Limited time offer - act fast!",
        "Deal of the day expires soon!",
        "Hurry! Only {m} minutes left to claim 50% off!",
        "Discount code valid for the next {m} minutes only!",
        "Don't wait! Flash sale ending shortly!",
        "Final hours! Special promotional price ends today!",
        "Hurry up! Price goes back up at midnight!",
        "Time is running out! Lock in your low rate now!",
        "Countdown timer: {m} mins {s} secs remaining!",
        "Act now before this deal vanishes!",
        "Urgent! Claim your free gift within {m} minutes!",
        "Offer expiring! Complete your reservation now!",
        "Last chance! Offer ends in {m}:{s}!",
        "Hurry, discount applies only if purchased right now!",
        "Clock is ticking! Get 30% off before timer expires!",
        "Only {m} minutes left to qualify for free express shipping!",
        "Flash Sale! Prices revert to full price in {m} minutes!",
        "Hurry! Sale price available for a limited time only!"
    ]
    urgency_samples = []
    for tmpl in urgency_templates:
        for m in [2, 5, 10, 15, 30, 45]:
            for s in [0, 15, 30, 45, 59]:
                text = tmpl.format(m=f"{m:02d}", s=f"{s:02d}")
                urgency_samples.append(text)
                urgency_samples.append(text.upper())
                urgency_samples.append("⚡ " + text)

    # 3. SCARCITY SAMPLES
    scarcity_templates = [
        "Only {n} items left in stock!",
        "Hurry! Only {n} left - order soon!",
        "High demand! Only {n} units available!",
        "Almost sold out! Only {n} remaining in warehouse!",
        "Stock is extremely low - only {n} items remaining!",
        "{n} people have this product in their cart right now!",
        "Over {n} people are viewing this offer currently!",
        "Limited stock available! Only {n} items left for immediate dispatch!",
        "Popular item! Only {n} left in our inventory!",
        "Hurry up! Just {n} spots available at this price!",
        "Selling fast! Only {n} left in stock!",
        "Only {n} left at this discounted rate!",
        "Low inventory warning: only {n} units remain!",
        "In high demand! {n} purchased in the last hour!",
        "Only {n} items left before backorder!"
    ]
    scarcity_samples = []
    for tmpl in scarcity_templates:
        for n in [1, 2, 3, 4, 5, 7, 9, 12, 15, 23, 48]:
            text = tmpl.format(n=n)
            scarcity_samples.append(text)
            scarcity_samples.append("🔥 " + text)
            scarcity_samples.append("⚠️ " + text)

    # 4. CONFIRMSHAMING SAMPLES
    confirmshaming_templates = [
        "No, I don't want to save money and prefer paying full price",
        "No thanks, I don't care about saving money",
        "Nah, I prefer paying full price for items",
        "No, I don't want free shipping and exclusive discounts",
        "No thanks, I hate saving money",
        "No, I prefer being uninformed and losing out on deals",
        "Nah, I don't care about my security and privacy",
        "No thanks, I don't want a 20% discount on my purchase",
        "No, I don't want to protect my account with security updates",
        "No, I enjoy paying more money",
        "No thanks, I'd rather miss out on amazing savings",
        "Nah, I don't want to improve my skills and stay behind",
        "No, I prefer wasting time and paying full price",
        "No thanks, I don't want free unlimited access",
        "No, I don't care about getting the best value",
        "Nah, I'll pass on saving $50 today",
        "No thanks, I prefer paying extra fees",
        "No, I don't want VIP perks and special benefits",
        "No, keep my order expensive",
        "Nah, I don't want to protect my purchase warranty"
    ]
    confirmshaming_samples = []
    prefix_suffix = [
        ("", ""), ("Click here: ", ""), ("Option: ", ""), ("Select: ", ""),
        ("", " - I'll pay full price"), ("", " (I'll pass)"), ("No thanks, ", "")
    ]
    for tmpl in confirmshaming_templates:
        for p, s in prefix_suffix:
            confirmshaming_samples.append(p + tmpl + s)

    # 5. FORCED ACTION SAMPLES
    forced_action_templates = [
        "You must create an account and subscribe to promotional emails to complete checkout",
        "Mandatory newsletter registration required to proceed to download",
        "You are required to share your location and contact list to access this feature",
        "Account creation and promotional consent required to view price",
        "Required: Subscribe to our partner offers to unlock your free trial",
        "You must allow push notifications to continue using this website",
        "Mandatory survey completion required before downloading your file",
        "To continue, you must agree to receive daily promotional SMS messages",
        "Required action: Join our rewards program to complete your order",
        "You must download our toolbar application to view this content",
        "Compulsory registration: enter phone number and permit marketing calls to proceed",
        "Must agree to mandatory data sharing to access free content",
        "To read this article, you must subscribe to our daily email newsletter",
        "Required step: consent to third-party marketing to enable button",
        "Mandatory software installation required to proceed to website"
    ]
    forced_action_samples = []
    fa_modifiers = ["", " [Required]", " (Mandatory)", " - Action Required", " -> Must agree to continue"]
    for tmpl in forced_action_templates:
        for mod in fa_modifiers:
            forced_action_samples.append(tmpl + mod)
            forced_action_samples.append("⚠️ " + tmpl + mod)

    # 6. PRESELECTION SAMPLES
    preselection_templates = [
        "Pre-checked: Automatically sign me up for weekly marketing emails and partner offers",
        "Checked by default: Add $4.99 premium shipping protection insurance to my order",
        "Selected: Automatically renew my subscription every month at full price",
        "Pre-selected: Enroll me in auto-bill pay and recurring monthly membership",
        "Pre-checked: I agree to receive marketing communications from 50+ third-party sponsors",
        "Checked by default: Add optional magazine subscription ($9.99/mo) to cart",
        "Pre-selected box: Opt-in to promotional SMS text messaging and robo-calls",
        "Default checked: Share my browsing profile with advertising network partners",
        "Pre-selected: Automatically add extended warranty package ($14.99) to checkout",
        "Pre-checked: Sign me up for VIP rewards club membership ($19.99/month)",
        "Checked by default: Keep me logged in and allow persistent tracking cookies",
        "Pre-selected: Upgrade my ticket to non-refundable premium tier automatically",
        "Default checked option: Subscribe to newsletter and agree to partner data access",
        "Pre-checked checkbox: Opt-in to marketing telemetry and behavior profiling",
        "Pre-selected default: Add optional carbon offset donation ($2.50) to order"
    ]
    preselection_samples = []
    for tmpl in preselection_templates:
        for mod in ["", " (Checked)", " [Default On]", " (Pre-selected)", " - Auto-enrolled"]:
            preselection_samples.append(tmpl + mod)

    # 7. MISDIRECTION SAMPLES
    misdirection_templates = [
        "Accept All & Continue (Recommended) vs [Tiny link: Decline & customize]",
        "Big Green Button: ACCEPT ALL EXTRA CHARGES | Small grey text: Skip optional add-on",
        "Confusing wording: Uncheck this box if you DO NOT wish to NOT receive promotional offers",
        "Deceptive choice: Click 'Cancel' to proceed with order, or 'OK' to abort",
        "Visually prominent 'ACCEPT ALL SPONSORS' vs hidden invisible 'Reject all' button",
        "Misleading button label: 'Continue Free Trial' secretly charges $49.99 after 3 days",
        "Confusing double negative: Check box to refrain from not receiving marketing emails",
        "Primary highlighted button: 'ADD EVERYTHING TO CART' | Hidden text: 'No thanks'",
        "Deceptive button: 'Download Now' installs third-party adware instead of software",
        "Visual hierarchy trick: Huge 'UPGRADE NOW' button next to faded unclickable 'No thanks'",
        "Misleading opt-out: 'Keep my discount' actually subscribes you to paid membership",
        "Ambiguous action: 'Yes, don't show this again' enables background data collection",
        "Trick phrasing: Check if you do not want us to refrain from sharing your data",
        "Prominent 'AGREE & PAY' button vs disguised 'Manage preferences' hyperlink",
        "Misleading layout: 'X' button on popup actually opens promotional offer page"
    ]
    misdirection_samples = []
    for tmpl in misdirection_templates:
        for mod in ["", " [Misleading UI]", " (Deceptive Button)", " - Visual Trickery", " -> Misdirection"]:
            misdirection_samples.append(tmpl + mod)

    # 8. PRIVACY MANIPULATION SAMPLES
    privacy_templates = [
        "We value your privacy: Accept All Cookies & Data Selling (One-click) vs 15-step manual opt-out",
        "Allow all 500+ ad partners to track your activity across websites for personalized ads",
        "Deceptive consent: Click 'I Agree' to sell your personal location and demographic data",
        "Obstacle-ridden privacy controls: Rejecting cookies requires toggling 200 individual vendor switches",
        "Forced tracking consent: You must accept cross-site tracking cookies to view this page",
        "Privacy manipulation: 'Accept All Cookies' button highlighted, 'Reject All' button disabled/hidden",
        "Misleading cookie banner: 'By remaining on this site you consent to full data collection & ad profiling'",
        "Deceptive privacy setting: 'Enhance your experience' secretly enables microphone & location telemetry",
        "Hard-to-find opt-out: 'Do Not Sell My Personal Information' link hidden in footer 8pt font",
        "Privacy confirmshaming: 'No, I don't care about my online privacy and safety'",
        "Pre-checked privacy consent: Automatically agree to share personal data with third-party brokers",
        "Confusing privacy toggle: 'Disable Non-Essential Data Selling' (Default: OFF)",
        "Deceptive consent renewal: Popup demands cookie permission repeatedly until user clicks Accept All",
        "Manipulative privacy choice: 'Allow tracking to keep service free' vs 'Pay $10/mo to opt-out of tracking'",
        "Deceptive account privacy: Default settings set user profile, photos, and location to Public"
    ]
    privacy_samples = []
    for tmpl in privacy_templates:
        for mod in ["", " [Privacy Dark Pattern]", " (Cookie Consent Trick)", " - Data Exploitation", " -> Privacy Violation"]:
            privacy_samples.append(tmpl + mod)

    # Compile dataset into list of (text, label)
    dataset = []

    def add_samples(samples, label, count_target=450):
        # Generate variations to reach count_target
        current = list(set(samples))
        expanded = []
        prefixes = ["", "Notice: ", "Alert: ", "Update: ", "Important: ", "UI Element: ", "Button: ", "Popup: ", "Banner: ", "Checkbox: "]
        suffixes = ["", ".", "!", " - Click here", " (Now)", " [Details]", " -> Learn more", " - Submit"]
        
        idx = 0
        while len(expanded) < count_target:
            base = current[idx % len(current)]
            p = prefixes[(idx // len(current)) % len(prefixes)]
            s = suffixes[(idx // len(current)) % len(suffixes)]
            item = (p + base + s).strip()
            expanded.append(item)
            idx += 1
        
        # Deduplicate preserving order
        seen = set()
        final_list = []
        for text in expanded:
            if text not in seen:
                seen.add(text)
                final_list.append((text, label))
        return final_list[:count_target]

    dataset.extend(add_samples(normal_samples, "normal", 500))
    dataset.extend(add_samples(urgency_samples, "urgency", 450))
    dataset.extend(add_samples(scarcity_samples, "scarcity", 450))
    dataset.extend(add_samples(confirmshaming_samples, "confirmshaming", 450))
    dataset.extend(add_samples(forced_action_samples, "forced_action", 450))
    dataset.extend(add_samples(preselection_samples, "preselection", 450))
    dataset.extend(add_samples(misdirection_samples, "misdirection", 450))
    dataset.extend(add_samples(privacy_samples, "privacy_manipulation", 450))

    # Shuffle dataset deterministically
    random.shuffle(dataset)

    output_path = os.path.join("ml", "dataset.csv")
    with open(output_path, "w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["text", "label"])
        for text, label in dataset:
            writer.writerow([text, label])

    print(f"Generated {len(dataset)} balanced, high-quality samples in {output_path}")
    from collections import Counter
    counts = Counter([label for text, label in dataset])
    for label, count in counts.items():
        print(f"  - {label}: {count} samples")

if __name__ == "__main__":
    generate_dataset()

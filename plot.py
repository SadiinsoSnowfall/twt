#!/usr/bin/env python3

from dataclasses import dataclass
from pathlib import Path
from datetime import datetime
import sqlite3
import matplotlib.pyplot as plt
from collections import Counter
import numpy as np

import locale
locale.setlocale(locale.LC_ALL, 'en_us')

@dataclass
class User:
    id: int
    name: str
    reason: str
    match: str
    date: str
    premium: int
    creation_date: str
    posts: int
    followers: int

def fetch_data():
    conn = sqlite3.connect('storage.db')
    cursor = conn.cursor()

    cursor.execute('SELECT id, name, reason, match, date, premium, creation_date, posts, followers FROM users')
    rows = cursor.fetchall()
    cursor.close()
    conn.close()

    users = [ User(
        id=row[0],
        name=row[1],
        reason=row[2],
        match=row[3],
        date=datetime.strptime(row[4], '%Y-%m-%d'),
        premium=row[5],
        creation_date=datetime.strptime(row[6], '%Y-%m-%d'),
        posts=row[7],
        followers=row[8]
    ) for row in rows ]
    
    return users

users = fetch_data()

output_folder = Path('plots')
output_folder.mkdir(exist_ok=True)

##############################
# plot followers distribution
##############################
def categorize_followers(count):
    if count < 10:
        return "< 10"
    elif count < 100:
        return "10-100"
    elif count < 1000:
        return "100-1K"
    elif count < 10000:
        return "1K-10K"
    elif count < 100000:
        return "10K-100K"
    elif count < 1000000:
        return "100K-1M"
    else:
        return "1M+"

followers_counts = [user.followers for user in users]
categories = [categorize_followers(count) for count in followers_counts]
category_counts = Counter(categories)
category_order = ["< 10", "10-100", "100-1K", "1K-10K", "10K-100K", "100K-1M", "1M+"]
counts = [category_counts.get(cat, 0) for cat in category_order]

total_users = len(followers_counts)
mean_followers = np.mean(followers_counts)
median_followers = np.median(followers_counts)
max_followers = max(followers_counts)

plt.figure(figsize=(12, 8))
bars = plt.bar(category_order, counts, alpha=0.7, color='skyblue', edgecolor='black')
plt.xlabel('Number of Followers')
plt.ylabel('Number of Users')
plt.title(f'Distribution of Followers Among Blocked Users\nMean: {mean_followers:.0f} | Median: {median_followers:.0f} | Max: {max_followers:n} | Total: {total_users:,}')
plt.grid(True, alpha=0.3, axis='y')

for bar, count in zip(bars, counts):
    if count > 0:
        percentage = (count / total_users) * 100
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(counts)*0.01, 
                f'{count}\n({percentage:.2f}%)', ha='center', va='bottom')


plt.ylim(0, max(counts) * 1.1)
plt.tight_layout()
plt.savefig(output_folder / 'followers_distribution.png', dpi=300, bbox_inches='tight')

##########################
# plot posts distribution
##########################
def categorize_posts(count):
    if count < 10:
        return "< 10"
    elif count < 100:
        return "10-100"
    elif count < 1000:
        return "100-1K"
    elif count < 10000:
        return "1K-10K"
    elif count < 100000:
        return "10K-100K"
    else:
        return "100K+"

post_count = [user.posts for user in users]
categories = [categorize_posts(count) for count in post_count]
category_counts = Counter(categories)
category_order = ["< 10", "10-100", "100-1K", "1K-10K", "10K-100K", "100K+"]
counts = [category_counts.get(cat, 0) for cat in category_order]

total_users = len(post_count)
mean_posts = np.mean(post_count)
median_posts = np.median(post_count)
max_posts = max(post_count)

plt.figure(figsize=(12, 8))
bars = plt.bar(category_order, counts, alpha=0.7, color='skyblue', edgecolor='black')
plt.xlabel('Number of Posts')
plt.ylabel('Number of Users')
plt.title(f'Distribution of Posts Count Among Blocked Users\nMean: {mean_posts:.0f} | Median: {median_posts:.0f} | Max: {max_posts:n} | Total: {total_users:,}')
plt.grid(True, alpha=0.3, axis='y')

for bar, count in zip(bars, counts):
    if count > 0:
        percentage = (count / total_users) * 100
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(counts)*0.01, 
                f'{count}\n({percentage:.2f}%)', ha='center', va='bottom')


plt.ylim(0, max(counts) * 1.1)
plt.tight_layout()
plt.savefig(output_folder / 'posts_distribution.png', dpi=300, bbox_inches='tight')

##################################
# plot creation date distribution
##################################

creation_years = [user.creation_date.year for user in users]
year_counts = Counter(creation_years)

sorted_years = sorted(year_counts.keys())
year_values = [year_counts[year] for year in sorted_years]

plt.figure(figsize=(14, 8))
bars = plt.bar(sorted_years, year_values, alpha=0.7, color='lightcoral', edgecolor='black')
plt.xlabel('Account Creation Year')
plt.ylabel('Number of Users')
plt.title(f'Distribution of Account Creation Dates for Blocked Users\nTotal Users: {len(users):,}')
plt.grid(True, alpha=0.3, axis='y')

for bar, count in zip(bars, year_values):
    if count > 0:
        percentage = (count / len(users)) * 100
        plt.text(bar.get_x() + bar.get_width()/2, bar.get_height() + max(year_values)*0.01, 
                f'{count}\n({percentage:.1f}%)', ha='center', va='bottom', fontsize=9)

plt.xticks(sorted_years, rotation=45)
plt.ylim(0, max(year_values) * 1.15)
plt.tight_layout()
plt.savefig(output_folder / 'creation_date_distribution.png', dpi=300, bbox_inches='tight')

##################################
# plot most common ending digits
##################################

import re

# Extract usernames that end with exactly two digits (not preceded by another digit)
two_digit_endings = []
for user in users:
    # Use regex to find usernames ending with exactly two digits (not part of a longer sequence)
    match = re.search(r'(?<!\d)(\d{2})$', user.name)
    if match:
        two_digit_endings.append(match.group(1))

# Count the occurrences of each two-digit ending
ending_counts = Counter(two_digit_endings)

# Get only the top 10 endings (no "Others" category)
top_endings = ending_counts.most_common(10)
total_two_digit_count = len(two_digit_endings)

# Prepare data for pie chart
labels = [ending for ending, count in top_endings]
sizes = [count for ending, count in top_endings]

# Calculate percentages relative to total, not just top 10
def autopct_format(pct):
    # Convert the percentage back to count and recalculate based on total
    count = int(round(pct * sum(sizes) / 100))
    real_pct = (count / total_two_digit_count) * 100
    return f'{real_pct:.1f}%'

# Create explode values to separate slices equally for better readability
explode = [0.05] * len(labels)  # Small uniform spacing between all slices

# Create a pie chart
plt.figure(figsize=(12, 10))

# Create pie chart with custom percentage calculation
wedges, texts, autotexts = plt.pie(sizes, labels=labels, explode=explode, autopct=autopct_format, startangle=90, 
                                  textprops={'fontsize': 8})

plt.title(f'Most Common Two-Digit Username Endings\nTotal usernames ending with digits: {len(two_digit_endings)}', 
            fontsize=14, pad=20)

# Style the default labels with bigger font and boxes
for text in texts:
    text.set_fontsize(14)
    text.set_fontweight('bold')
    text.set_bbox(dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='black', alpha=0.8))

# Style the percentage labels
for autotext in autotexts:
    autotext.set_color('black')
    autotext.set_fontweight('bold')
    autotext.set_fontsize(10)

# Add a legend with counts
legend_labels = [f'{label}: {size} users' for label, size in zip(labels, sizes)]

plt.legend(wedges, legend_labels, title="Endings", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))

plt.tight_layout()
plt.savefig(output_folder / 'two_digit_endings_pie.png', dpi=300, bbox_inches='tight')


############################################
# plot most common ending digits (per year)
############################################

# Create output folder for per-year charts
year_output_folder = output_folder / 'ending_per_year'
year_output_folder.mkdir(exist_ok=True)

# Group users by creation year
users_by_year = {}
for user in users:
    year = user.creation_date.year
    if year not in users_by_year:
        users_by_year[year] = []
    users_by_year[year].append(user)

# Create a pie chart for each year
for year in sorted(users_by_year.keys()):
    year_users = users_by_year[year]
    
    # Extract usernames that end with exactly two digits for this year
    year_two_digit_endings = []
    for user in year_users:
        match = re.search(r'(?<!\d)(\d{2})$', user.name)
        if match:
            year_two_digit_endings.append(match.group(1))
    
    # Skip years with too few two-digit endings
    if len(year_two_digit_endings) < 5:
        continue
    
    # Count the occurrences of each two-digit ending for this year
    year_ending_counts = Counter(year_two_digit_endings)
    
    # Get only the top 10 endings for this year
    year_top_endings = year_ending_counts.most_common(10)
    total_year_count = len(year_two_digit_endings)
    
    # Prepare data for pie chart
    year_labels = [ending for ending, count in year_top_endings]
    year_sizes = [count for ending, count in year_top_endings]
    
    # Calculate percentages relative to total for this year
    def year_autopct_format(pct):
        count = int(round(pct * sum(year_sizes) / 100))
        real_pct = (count / total_year_count) * 100
        return f'{real_pct:.1f}%'
    
    # Create explode values
    year_explode = [0.05] * len(year_labels)
    
    # Create a pie chart for this year
    plt.figure(figsize=(12, 10))
    
    wedges, texts, autotexts = plt.pie(year_sizes, labels=year_labels, explode=year_explode, 
                                      autopct=year_autopct_format, startangle=90, 
                                      textprops={'fontsize': 8})
    
    plt.title(f'Most Common Two-Digit Username Endings - {year}\n'
              f'Users created in {year}: {len(year_users):,} | '
              f'With two-digit endings: {total_year_count:,}', 
              fontsize=14, pad=20)
    
    # Style the labels with bigger font and boxes
    for text in texts:
        text.set_fontsize(14)
        text.set_fontweight('bold')
        text.set_bbox(dict(boxstyle='round,pad=0.3', facecolor='white', edgecolor='black', alpha=0.8))
    
    # Style the percentage labels
    for autotext in autotexts:
        autotext.set_color('black')
        autotext.set_fontweight('bold')
        autotext.set_fontsize(10)
    
    # Add a legend with counts
    year_legend_labels = [f'{label}: {size} users' for label, size in zip(year_labels, year_sizes)]
    plt.legend(wedges, year_legend_labels, title="Endings", loc="center left", bbox_to_anchor=(1, 0, 0.5, 1))
    
    plt.tight_layout()
    plt.savefig(year_output_folder / f'two_digit_endings_{year}.png', dpi=300, bbox_inches='tight')
    plt.close()  # Close the figure to free memory

###################
# print misc stats
###################

most_followers_user = max(users, key=lambda u: u.followers)
print(f'User with most followers: @{most_followers_user.name} ({most_followers_user.followers} followers)  - reason: {most_followers_user.reason}/{most_followers_user.match}')

most_posts_user = max(users, key=lambda u: u.posts)
print(f'User with most posts: @{most_posts_user.name} ({most_posts_user.posts} posts) - reason: {most_posts_user.reason}/{most_posts_user.match}')

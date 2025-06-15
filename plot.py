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

    cursor.execute('SELECT id, name, reason, match, date, premium, creation_date, posts, followers FROM users where blocked = 1 and followers is not null')
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

###################
# print misc stats
###################

most_followers_user = max(users, key=lambda u: u.followers)
print(f'User with most followers: @{most_followers_user.name} ({most_followers_user.followers} followers)  - reason: {most_followers_user.reason}/{most_followers_user.match}')

most_posts_user = max(users, key=lambda u: u.posts)
print(f'User with most posts: @{most_posts_user.name} ({most_posts_user.posts} posts) - reason: {most_posts_user.reason}/{most_posts_user.match}')

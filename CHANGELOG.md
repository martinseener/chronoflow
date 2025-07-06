# Changelog

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [1.1.1] - 2025-07-06

### Bugfixes
- Fixed earnings calculation precision errors that caused totals to be off by 1 cent
  - Earnings calculations now properly round to 2 decimal places

## [1.1.0] - 2025-07-05

### Added
- Footer with version display at the bottom of the dashboard
- Separate earnings breakdown in time history summary:
  - Open Earnings: Shows earnings from pending entries
  - Invoiced Earnings: Shows earnings from invoiced entries
  - Total Earnings: Shows combined earnings (unchanged)

## [1.0.1] - 2025-07-05

### Bugfixes
- CSV/JSON exports now use local timezone instead of UTC time
- Unbilled entries earnings now set to 0 and removed from total earnings calculation (reversable)
- Add password confirmation field for registrations to minimize risk of typos

## [1.0.0] - 2025-07-03

### Added
- Released v1.0.0 of Chronoflow to the public

# dress-shop: an over-engineered shop backend, measured with ISO/IEC 5055

dress-shop is the REST backend of an online clothing shop: **Express + TypeScript + MongoDB (Mongoose)**, with JWT and
Google sign-in (Passport), Cloudinary uploads, carts, wishlists, orders, payments, deliveries and reviews.

Last year the team refactored it pull request by pull request, applying one principle or pattern at a time
(the full history is kept in this repo):

| Family | Applied |
|---|---|
| SOLID | SRP (services + shared), LSP, ISP (user contracts), OCP (payment processors), DIP (repositories + DI) |
| GRASP | Information Expert, High Cohesion, Creator, Low Coupling |
| GoF | Builder (order), Factory Method (users), Facade (checkout), Observer (reviews, products), State (delivery) |
| Design by contract | OCL constraints (wishlist, delivery) |

## The question
After all these patterns, is the code good quality by an international standard?
We measured every milestone of the history with **SonarQube Community Build** and mapped the results to
**ISO/IEC 5055** (Security, Reliability, Performance Efficiency, Maintainability).

Short answer: one refactoring (SRP) removed real weaknesses; the others made the code bigger and more complex while
the same weaknesses stayed. Patterns are not a guarantee of ISO 5055 quality.
The full results, the method and a video tutorial are in the audit repo:
https://github.com/inesCherif/domiaffaire-iso5055-audit (folder `final/`).

## Run it
```bash
cp .env.example .env          # fill in your own values
npm install --legacy-peer-deps
npm run dev                   # http://localhost:<PORT>
```

## Scan it with SonarQube
SonarQube running on http://localhost:9000 (see the tutorial), dependencies installed, then:
```bash
docker run --rm --network host -e SONAR_HOST_URL=http://localhost:9000 -e SONAR_TOKEN \
  -v "$PWD:/usr/src" sonarsource/sonar-scanner-cli
```
The settings are in `sonar-project.properties`. Use the **Sonar way comprehensive** quality profile for TypeScript:
the default one ("Sonar way core") hides most maintainability rules.

# Report HTML Styling Guide

## Overview

This guide defines the consistent styling patterns for the Application Exposure Report HTML template. All styling uses Tailwind CSS with a custom configuration.

## Design Tokens

### Colors

**Semantic Colors (Tailwind Standard)**

**Text Colors**
- Primary Headings: `text-gray-800`
- Secondary Headings: `text-gray-700`
- Body Text: `text-gray-700`
- Muted/Labels: `text-gray-600`
- Hints/Meta: `text-gray-500`

**Links & Accents**
- Links: `text-blue-500` (hover: `hover:text-blue-600`)
- Icons/Accents: `text-blue-500`
- Accent Borders: `border-blue-500`

**Backgrounds**
- Cards: `bg-white`
- Alternating Rows: `bg-gray-50`
- Headers: `bg-gray-100`
- Info Boxes: `bg-blue-50` with `border-blue-200`

**Borders**
- Light: `border-[#e7eaed]`
- Accent: `border-[#C4CFE8]`
- Divider: `border-gray-200`

**DO NOT USE**: Custom hex colors in text classes. Always use Tailwind's semantic colors.

**Criticality Colors**
- Critical (5): `#6B2C28`
- High (4): `#C13832`
- Medium (3): `#C1603D`
- Low (2): `#C19A3E`
- Minimal (1): `#B8B8B8`

**Risk Gradient Colors**
- High Risk: `#fee2e2` to `#fecaca` (text: `#991b1b`)
- Medium Risk: `#fef3c7` to `#fde68a` (text: `#92400e`)
- Low Risk: `#dcfce7` to `#bbf7d0` (text: `#166534`)

### Typography

**Font Family**
- Base: `font-montserrat` (Montserrat, sans-serif)

**Heading Sizes**
```
h1 (Report Title):      text-2xl font-bold        (24px)
h2 (Section):           text-xl font-semibold     (20px)
h3 (Subsection):        text-lg font-bold         (18px)
h4 (Card Title):        text-base font-bold       (16px)
```

**Body Text Sizes**
```
Large Body:    text-base   (16px)
Body:          text-sm     (14px)
Small:         text-xs     (12px)
Tiny Label:    text-[10px] (10px) - Use sparingly
Micro Label:   text-[9px]  (9px)  - Use sparingly
```

**Font Weights**
- Regular: `font-normal` (400)
- Medium: `font-medium` (500)
- Semibold: `font-semibold` (600)
- Bold: `font-bold` (700)

### Spacing

**Container Padding**
```
Page Container:     p-2.5    (10px)
Section Padding:    p-5      (20px)
Card Padding:       p-6      (24px)
Small Card:         p-3      (12px)
```

**Margins**
```
Section Bottom:     mb-6     (24px)
Card Bottom:        mb-5     (20px)
Element Bottom:     mb-4     (16px)
Small Bottom:       mb-3     (12px)
Tiny Bottom:        mb-2     (8px)
Label Bottom:       mb-1     (4px)
```

**Gaps (Flexbox/Grid)**
```
Large Gap:     gap-6  (24px)
Medium Gap:    gap-5  (20px)
Default Gap:   gap-4  (16px)
Small Gap:     gap-3  (12px)
Tiny Gap:      gap-2  (8px)
```

### Borders & Radius

**Border Styles**
```
Card Border:         border border-[#e7eaed]
Accent Border:       border border-[#C4CFE8]
Divider:            border-t border-[#e7eaed]
Left Accent:        border-l-4 border-blue-500
```

**Border Radius**
```
Card Radius:        rounded-2xl   (16px) - STANDARD for cards and sections
Medium Radius:      rounded-xl    (12px) - For smaller elements
Pill/Badge:         rounded-full
Small Radius:       rounded-lg    (8px)
```

**Design Philosophy**: Use generous rounded corners for a modern, friendly appearance.

### Shadows

```
Card Hover:         hover:shadow-lg
Card Active:        shadow-md
Subtle:            shadow-sm
```

## Component Patterns

### Cards (Containers)

**Standard Section Card**
```html
<div class="bg-white border border-[#e7eaed] rounded-2xl p-5 mb-5">
    <h3 class="text-lg font-bold text-gray-800 mb-3">Section Title</h3>
    <p class="text-sm text-gray-700 mb-4 leading-relaxed">Description</p>
</div>
```

**Hero Card**
```html
<div class="bg-white border border-[#e7eaed] rounded-2xl p-6 mb-6">
    <h1 class="text-2xl font-semibold text-gray-800 mb-2">Main Title</h1>
</div>
```

**Metric Card (Stats)**
```html
<div class="flex flex-col justify-center px-4 py-3 rounded-2xl border border-[#C4CFE8] bg-gradient-card">
    <p class="text-xs font-medium text-gray-600 mb-1">Label</p>
    <p class="text-3xl font-bold text-gray-800 leading-none">123</p>
</div>
```

### Tables

**Standard Table**
```html
<table class="w-full border-separate bg-white rounded-2xl overflow-hidden border border-[#e7eaed]" style="border-spacing: 0;">
    <thead>
        <tr class="bg-gray-100">
            <th class="text-left p-3 font-semibold text-sm text-gray-700">Header</th>
        </tr>
    </thead>
    <tbody>
        <tr class="even:bg-gray-50">
            <td class="p-3 align-top text-sm">Content</td>
        </tr>
    </tbody>
</table>
```

### Badges & Pills

**Compliance Badge (Header)**
```html
<div class="px-3 py-1 rounded-full border border-[#C4CFE8] bg-gradient-card-subtle">
    <p class="text-xs font-medium text-gray-700">Badge Text</p>
</div>
```

**Technology Tag**
```html
<div class="flex items-center gap-2 px-3 py-2 rounded-2xl border border-[#C4CFE8] bg-gradient-card-subtle">
    <p class="text-xs font-medium text-gray-600">Technology</p>
    <p class="text-sm font-bold text-gray-800">Count</p>
</div>
```

### Accent Cards

**Detail Card (Appendix)**
```html
<div class="bg-gradient-card-subtle border border-[#e7eaed] rounded-2xl p-4">
    <h4 class="text-base font-bold text-gray-800 mb-2">Title</h4>
    <p class="text-sm text-gray-700 leading-relaxed">Description text</p>
</div>
```

**Note**: Use subtle gradient background for detail cards in appendix sections.

### Links

**Standard Link**
```html
<a href="#target" class="text-blue-500 hover:text-blue-600 hover:underline">Link Text</a>
```

**Help Icon Link (Appendix Reference)**
```html
<a href="#appendix-section" class="text-gray-600 hover:text-gray-800 transition-colors no-underline">
    <i class="far fa-circle-question text-xs"></i>
</a>
```

**Note**: Use `far` (regular/hollow) instead of `fas` (solid/filled) for a lighter appearance. Use gray colors for help icons to keep them subtle.

**Card Link (Clickable Card)**
```html
<a href="#section" class="flex flex-col px-4 py-4 rounded-2xl border border-[#C4CFE8] no-underline hover:shadow-lg transition-shadow cursor-pointer bg-gradient-card">
    Content
</a>
```

## Gradients (CSS Custom Properties)

Add to `<style>` section:

```css
:root {
    /* Card Gradients */
    --gradient-card: linear-gradient(148.39deg, rgba(255,255,255,0.3) -34.39%, rgba(217,228,255,0.3) 102.8%);
    --gradient-card-subtle: linear-gradient(148.39deg, rgba(255,255,255,0.3) -34.39%, rgba(231,236,238,0.3) 102.8%);
}

.bg-gradient-card {
    background: var(--gradient-card);
}

.bg-gradient-card-subtle {
    background: var(--gradient-card-subtle);
}
```

## Responsive Design

**Grid Layouts**
```
4 columns:     grid grid-cols-4 gap-4
5 columns:     grid grid-cols-5 gap-4
Responsive:    grid grid-cols-1 md:grid-cols-2 lg:grid-cols-4 gap-4
```

**Flexbox Layouts**
```
Horizontal:    flex items-center gap-3
Vertical:      flex flex-col gap-3
Space Between: flex justify-between items-center
```

## Print Styles

Already defined in template. Key rules:
- Page size: A4, margin 0.3in
- Avoid page breaks inside table rows
- Use `.page-break-before` class for section breaks
- Hide `.no-print` elements

## Migration Checklist

### Replace These Patterns

❌ **Old (Inconsistent)**
```
rounded-[20px]           → rounded-xl
text-[13px]             → text-sm
text-[24px]             → text-2xl
text-[32px]             → text-3xl
px-4 py-4               → p-4
inline style gradients  → bg-gradient-card class
```

✅ **New (Consistent)**
```
rounded-xl
text-sm
text-2xl
text-3xl
p-4
bg-gradient-card
```

### Heading Consistency

Replace:
- `text-gray-800 text-2xl mb-5 font-bold` → `text-2xl font-bold text-gray-800 mb-5`
- Reorder: size → weight → color → spacing

### Color Consistency

Replace custom colors with CSS variables:
1. Define colors in `:root`
2. Use `var(--color-name)` in inline styles
3. Prefer Tailwind utilities when possible

## Examples

### Before (Inconsistent)
```html
<div class="bg-white border border-[#e7eaed] rounded-[20px] p-5 mb-5">
    <h3 class="text-lg font-bold text-gray-800 mb-3">Title</h3>
    <div class="px-3 py-1 rounded-[20px]" style="background: linear-gradient(148.39deg, rgba(255,255,255,0.3) -34.39%, rgba(217,228,255,0.3) 102.8%);">
        <p class="text-[11px] font-medium text-[#364750]">Badge</p>
    </div>
</div>
```

### After (Consistent)
```html
<div class="bg-white border border-[#e7eaed] rounded-2xl p-5 mb-5">
    <h3 class="text-lg font-bold text-gray-800 mb-3">Title</h3>
    <div class="px-3 py-1 rounded-full bg-gradient-card">
        <p class="text-xs font-medium text-gray-700">Badge</p>
    </div>
</div>
```

## Maintenance

When adding new components:
1. Check this guide first
2. Use existing patterns
3. Avoid arbitrary values unless absolutely necessary
4. Document new patterns if required
5. Update this guide when adding new tokens

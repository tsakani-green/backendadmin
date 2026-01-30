import requests

# Test the carbon emissions calculation with the new formula
try:
    print('=== Testing Carbon Emissions Formula ===\n')
    print('Formula: tCO₂e = kWh × 0.93 ÷ 1000\n')
    
    # Test examples
    test_cases = [
        {"kwh": 1000, "expected_tco2e": 1000 * 0.93 / 1000},
        {"kwh": 500, "expected_tco2e": 500 * 0.93 / 1000},
        {"kwh": 100, "expected_tco2e": 100 * 0.93 / 1000},
        {"kwh": 50, "expected_tco2e": 50 * 0.93 / 1000},
    ]
    
    print('Test Cases:')
    for case in test_cases:
        kwh = case["kwh"]
        expected = case["expected_tco2e"]
        print(f'  {kwh} kWh = {expected:.3f} tCO₂e')
    
    print(f'\nTesting carbon analysis endpoint...')
    
    # Test the carbon analysis endpoint
    response = requests.get('http://localhost:8002/api/analytics/carbon-analysis')
    print(f'Carbon Analysis Status: {response.status_code}')
    
    if response.status_code == 200:
        data = response.json()
        if data.get('status') == 'success':
            analysis = data.get('analysis', {})
            carbon_factor = analysis.get('carbon_factor_kg_per_kwh')
            total_carbon_tons = analysis.get('total_carbon_tons', 0)
            total_energy_kwh = analysis.get('total_energy_kwh', 0)
            
            print(f'  ✅ Carbon Factor: {carbon_factor} kgCO₂e/kWh')
            print(f'  ✅ Total Energy: {total_energy_kwh:.2f} kWh')
            print(f'  ✅ Total Carbon: {total_carbon_tons:.3f} tCO₂e')
            
            # Verify the calculation
            calculated_carbon = total_energy_kwh * 0.93 / 1000
            if abs(calculated_carbon - total_carbon_tons) < 0.001:
                print(f'  ✅ Formula verified: {total_energy_kwh:.2f} × 0.93 ÷ 1000 = {calculated_carbon:.3f} tCO₂e')
            else:
                print(f'  ❌ Formula mismatch: expected {calculated_carbon:.3f}, got {total_carbon_tons:.3f}')
        else:
            print(f'  Error: {data}')
    else:
        print(f'  Error: {response.text}')
    
    print(f'\nTesting energy insights endpoint...')
    
    # Test energy insights endpoint
    response = requests.get('http://localhost:8002/api/analytics/energy-insights')
    print(f'Energy Insights Status: {response.status_code}')
    
    if response.status_code == 200:
        data = response.json()
        if data.get('status') == 'success':
            insights = data.get('insights', {})
            carbon_potential = insights.get('carbon_reduction_potential', '0 tons CO₂e/month')
            print(f'  ✅ Carbon Reduction Potential: {carbon_potential}')
        else:
            print(f'  Error: {data}')
    else:
        print(f'  Error: {response.text}')
    
    print(f'\n=== Carbon Formula Test Complete ===')
    
except Exception as e:
    print(f'Test error: {e}')

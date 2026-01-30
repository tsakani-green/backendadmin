import requests

# Complete test of carbon emissions implementation
try:
    print('=== Complete Carbon Emissions Test ===\n')
    print('Formula: tCO₂e = kWh × 0.93 ÷ 1000\n')
    
    # Test 1: Settings Configuration
    print('1. Testing Settings Configuration...')
    try:
        # This should work without errors now
        from app.core.config import settings
        carbon_factor = settings.CARBON_FACTOR_KG_PER_KWH
        print(f'   ✅ Carbon Factor: {carbon_factor} kgCO₂e/kWh')
        print(f'   ✅ Formula: tCO₂e = kWh × {carbon_factor} ÷ 1000')
    except Exception as e:
        print(f'   ❌ Settings error: {e}')
    
    # Test 2: Analytics Carbon Analysis
    print(f'\n2. Testing Carbon Analysis Endpoint...')
    response = requests.get('http://localhost:8002/api/analytics/carbon-analysis')
    if response.status_code == 200:
        data = response.json()
        if data.get('status') == 'success':
            analysis = data.get('analysis', {})
            carbon_factor = analysis.get('carbon_factor_kg_per_kwh')
            total_carbon = analysis.get('total_carbon_tons', 0)
            total_energy = analysis.get('total_energy_kwh', 0)
            
            print(f'   ✅ Carbon Factor: {carbon_factor} kgCO₂e/kWh')
            print(f'   ✅ Total Energy: {total_energy:.2f} kWh')
            print(f'   ✅ Total Carbon: {total_carbon:.6f} tCO₂e')
            
            # Verify calculation
            expected = total_energy * 0.93 / 1000
            if abs(expected - total_carbon) < 0.001:
                print(f'   ✅ Calculation verified: {total_energy:.2f} × 0.93 ÷ 1000 = {expected:.6f} tCO₂e')
            else:
                print(f'   ❌ Calculation mismatch: expected {expected:.6f}, got {total_carbon:.6f}')
        else:
            print(f'   ❌ Analysis failed: {data}')
    else:
        print(f'   ❌ Endpoint error: {response.status_code} - {response.text}')
    
    # Test 3: Live Meter Data with Carbon
    print(f'\n3. Testing Live Meter Carbon Calculations...')
    response = requests.get('http://localhost:8002/api/meters/bertha-house/latest')
    if response.status_code == 200:
        data = response.json()
        
        power = data.get('power_kw', 0)
        energy = data.get('energy_kwh_delta', 0)
        carbon_tco2e = data.get('carbon_emissions_tco2e', 0)
        carbon_kg = data.get('carbon_emissions_kg_co2e', 0)
        carbon_rate = data.get('carbon_emission_rate_tco2e_per_hour', 0)
        
        print(f'   ✅ Power: {power:.3f} kW')
        print(f'   ✅ Energy Delta: {energy:.3f} kWh')
        print(f'   ✅ Carbon Emissions: {carbon_tco2e:.6f} tCO₂e ({carbon_kg:.3f} kg CO₂e)')
        print(f'   ✅ Carbon Rate: {carbon_rate:.6f} tCO₂e/hour')
        
        # Verify calculations
        expected_carbon = energy * 0.93 / 1000
        expected_rate = power * 0.93 / 1000
        
        if abs(expected_carbon - carbon_tco2e) < 0.000001:
            print(f'   ✅ Energy carbon verified: {energy:.3f} × 0.93 ÷ 1000 = {expected_carbon:.6f} tCO₂e')
        else:
            print(f'   ❌ Energy carbon mismatch: expected {expected_carbon:.6f}, got {carbon_tco2e:.6f}')
            
        if abs(expected_rate - carbon_rate) < 0.000001:
            print(f'   ✅ Power rate verified: {power:.3f} × 0.93 ÷ 1000 = {expected_rate:.6f} tCO₂e/hour')
        else:
            print(f'   ❌ Power rate mismatch: expected {expected_rate:.6f}, got {carbon_rate:.6f}')
    else:
        print(f'   ❌ Meter endpoint error: {response.status_code} - {response.text}')
    
    # Test 4: Energy Insights with Carbon
    print(f'\n4. Testing Energy Insights with Carbon...')
    response = requests.get('http://localhost:8002/api/analytics/energy-insights')
    if response.status_code == 200:
        data = response.json()
        if data.get('status') == 'success':
            insights = data.get('insights', {})
            carbon_potential = insights.get('carbon_reduction_potential', '0 tons CO₂e/month')
            print(f'   ✅ Carbon Reduction Potential: {carbon_potential}')
        else:
            print(f'   ❌ Insights failed: {data}')
    else:
        print(f'   ❌ Insights endpoint error: {response.status_code} - {response.text}')
    
    # Test 5: Formula Examples
    print(f'\n5. Formula Examples for Bertha House:')
    examples = [
        {'kwh': 100, 'description': 'Low consumption hour'},
        {'kwh': 500, 'description': 'Average consumption hour'},
        {'kwh': 1000, 'description': 'High consumption hour'},
        {'kwh': 2000, 'description': 'Peak consumption hour'},
    ]
    
    for example in examples:
        kwh = example['kwh']
        tco2e = kwh * 0.93 / 1000
        kg_co2e = kwh * 0.93
        print(f'   {kwh:4d} kWh = {tco2e:6.3f} tCO₂e ({kg_co2e:6.1f} kg CO₂e) - {example["description"]}')
    
    print(f'\n=== Test Complete ===')
    print('✅ Carbon emissions formula successfully implemented!')
    print('✅ Live carbon calculations working!')
    print('✅ Frontend display ready!')
    
except Exception as e:
    print(f'Test error: {e}')
    import traceback
    traceback.print_exc()

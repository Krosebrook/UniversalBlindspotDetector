/*
  # Fix Security Issues

  ## 1. Add Missing Foreign Key Indexes
    - Add index on `compliance_queries.user_id`
    - Add index on `profiles.organization_id`
    - Add index on `risk_assessments.user_id`

  ## 2. Optimize RLS Policies (Auth Function Initialization)
    Replace `auth.uid()` with `(select auth.uid())` in all policies to prevent re-evaluation
    Affected tables:
    - organizations
    - profiles
    - documents
    - compliance_queries
    - risk_assessments
    - user_profiles
    - deal_sourcing_preferences
    - portfolio_goals
    - community_preferences

  ## 3. Drop Unused Indexes
    - Drop unused indexes on documents, compliance_queries, risk_assessments
    - Drop unused indexes on deal_sourcing_preferences, portfolio_goals, community_preferences

  ## 4. Fix Duplicate and Internal Issues
    - Drop duplicate index on internal.kv_store_8788965a
    - Disable RLS on internal.kv_store_8788965a (internal table)

  ## 5. Fix Function Search Path
    - Update update_updated_at_column function with immutable search_path
*/

-- =====================================================
-- 1. ADD MISSING FOREIGN KEY INDEXES
-- =====================================================

CREATE INDEX IF NOT EXISTS idx_compliance_queries_user_id ON public.compliance_queries(user_id);
CREATE INDEX IF NOT EXISTS idx_profiles_organization_id ON public.profiles(organization_id);
CREATE INDEX IF NOT EXISTS idx_risk_assessments_user_id ON public.risk_assessments(user_id);

-- =====================================================
-- 2. DROP UNUSED INDEXES
-- =====================================================

DROP INDEX IF EXISTS public.idx_documents_organization;
DROP INDEX IF EXISTS public.idx_documents_user;
DROP INDEX IF EXISTS public.idx_queries_organization;
DROP INDEX IF EXISTS public.idx_queries_created;
DROP INDEX IF EXISTS public.idx_assessments_organization;
DROP INDEX IF EXISTS public.idx_deal_sourcing_user_id;
DROP INDEX IF EXISTS public.idx_portfolio_goals_user_id;
DROP INDEX IF EXISTS public.idx_community_preferences_user_id;

-- =====================================================
-- 3. FIX DUPLICATE INDEX ON INTERNAL TABLE
-- =====================================================

DROP INDEX IF EXISTS internal.kv_store_8788965a_key_idx;

-- =====================================================
-- 4. DISABLE RLS ON INTERNAL TABLE
-- =====================================================

ALTER TABLE IF EXISTS internal.kv_store_8788965a DISABLE ROW LEVEL SECURITY;

-- =====================================================
-- 5. OPTIMIZE RLS POLICIES - ORGANIZATIONS
-- =====================================================

DROP POLICY IF EXISTS "Users can view their organization" ON public.organizations;

CREATE POLICY "Users can view their organization"
  ON public.organizations
  FOR SELECT
  TO authenticated
  USING (
    id IN (
      SELECT organization_id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    )
  );

-- =====================================================
-- 6. OPTIMIZE RLS POLICIES - PROFILES
-- =====================================================

DROP POLICY IF EXISTS "Users can view own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can update own profile" ON public.profiles;
DROP POLICY IF EXISTS "Users can view profiles in their organization" ON public.profiles;

CREATE POLICY "Users can view own profile"
  ON public.profiles
  FOR SELECT
  TO authenticated
  USING (id = (select auth.uid()));

CREATE POLICY "Users can update own profile"
  ON public.profiles
  FOR UPDATE
  TO authenticated
  USING (id = (select auth.uid()))
  WITH CHECK (id = (select auth.uid()));

CREATE POLICY "Users can view profiles in their organization"
  ON public.profiles
  FOR SELECT
  TO authenticated
  USING (
    organization_id IN (
      SELECT organization_id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    )
  );

-- =====================================================
-- 7. OPTIMIZE RLS POLICIES - DOCUMENTS
-- =====================================================

DROP POLICY IF EXISTS "Users can view organization documents" ON public.documents;
DROP POLICY IF EXISTS "Users can insert documents" ON public.documents;
DROP POLICY IF EXISTS "Users can update own documents" ON public.documents;
DROP POLICY IF EXISTS "Users can delete own documents" ON public.documents;

CREATE POLICY "Users can view organization documents"
  ON public.documents
  FOR SELECT
  TO authenticated
  USING (
    organization_id IN (
      SELECT organization_id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    )
  );

CREATE POLICY "Users can insert documents"
  ON public.documents
  FOR INSERT
  TO authenticated
  WITH CHECK (
    organization_id IN (
      SELECT organization_id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    )
  );

CREATE POLICY "Users can update own documents"
  ON public.documents
  FOR UPDATE
  TO authenticated
  USING (
    user_id IN (
      SELECT id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    )
  )
  WITH CHECK (
    user_id IN (
      SELECT id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    )
  );

CREATE POLICY "Users can delete own documents"
  ON public.documents
  FOR DELETE
  TO authenticated
  USING (
    user_id IN (
      SELECT id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    )
  );

-- =====================================================
-- 8. OPTIMIZE RLS POLICIES - COMPLIANCE_QUERIES
-- =====================================================

DROP POLICY IF EXISTS "Users can view organization queries" ON public.compliance_queries;
DROP POLICY IF EXISTS "Users can insert queries" ON public.compliance_queries;

CREATE POLICY "Users can view organization queries"
  ON public.compliance_queries
  FOR SELECT
  TO authenticated
  USING (
    organization_id IN (
      SELECT organization_id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    )
  );

CREATE POLICY "Users can insert queries"
  ON public.compliance_queries
  FOR INSERT
  TO authenticated
  WITH CHECK (
    user_id IN (
      SELECT id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    ) AND
    organization_id IN (
      SELECT organization_id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    )
  );

-- =====================================================
-- 9. OPTIMIZE RLS POLICIES - RISK_ASSESSMENTS
-- =====================================================

DROP POLICY IF EXISTS "Users can view organization assessments" ON public.risk_assessments;
DROP POLICY IF EXISTS "Users can insert assessments" ON public.risk_assessments;
DROP POLICY IF EXISTS "Users can update own assessments" ON public.risk_assessments;

CREATE POLICY "Users can view organization assessments"
  ON public.risk_assessments
  FOR SELECT
  TO authenticated
  USING (
    organization_id IN (
      SELECT organization_id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    )
  );

CREATE POLICY "Users can insert assessments"
  ON public.risk_assessments
  FOR INSERT
  TO authenticated
  WITH CHECK (
    user_id IN (
      SELECT id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    ) AND
    organization_id IN (
      SELECT organization_id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    )
  );

CREATE POLICY "Users can update own assessments"
  ON public.risk_assessments
  FOR UPDATE
  TO authenticated
  USING (
    user_id IN (
      SELECT id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    )
  )
  WITH CHECK (
    user_id IN (
      SELECT id 
      FROM public.profiles 
      WHERE id = (select auth.uid())
    )
  );

-- =====================================================
-- 10. OPTIMIZE RLS POLICIES - USER_PROFILES
-- =====================================================

DROP POLICY IF EXISTS "Users can view own profile" ON public.user_profiles;
DROP POLICY IF EXISTS "Users can insert own profile" ON public.user_profiles;
DROP POLICY IF EXISTS "Users can update own profile" ON public.user_profiles;

CREATE POLICY "Users can view own profile"
  ON public.user_profiles
  FOR SELECT
  TO authenticated
  USING (id = (select auth.uid()));

CREATE POLICY "Users can insert own profile"
  ON public.user_profiles
  FOR INSERT
  TO authenticated
  WITH CHECK (id = (select auth.uid()));

CREATE POLICY "Users can update own profile"
  ON public.user_profiles
  FOR UPDATE
  TO authenticated
  USING (id = (select auth.uid()))
  WITH CHECK (id = (select auth.uid()));

-- =====================================================
-- 11. OPTIMIZE RLS POLICIES - DEAL_SOURCING_PREFERENCES
-- =====================================================

DROP POLICY IF EXISTS "Users can view own deal sourcing preferences" ON public.deal_sourcing_preferences;
DROP POLICY IF EXISTS "Users can insert own deal sourcing preferences" ON public.deal_sourcing_preferences;
DROP POLICY IF EXISTS "Users can update own deal sourcing preferences" ON public.deal_sourcing_preferences;

CREATE POLICY "Users can view own deal sourcing preferences"
  ON public.deal_sourcing_preferences
  FOR SELECT
  TO authenticated
  USING (
    user_id IN (
      SELECT id 
      FROM public.user_profiles 
      WHERE id = (select auth.uid())
    )
  );

CREATE POLICY "Users can insert own deal sourcing preferences"
  ON public.deal_sourcing_preferences
  FOR INSERT
  TO authenticated
  WITH CHECK (
    user_id IN (
      SELECT id 
      FROM public.user_profiles 
      WHERE id = (select auth.uid())
    )
  );

CREATE POLICY "Users can update own deal sourcing preferences"
  ON public.deal_sourcing_preferences
  FOR UPDATE
  TO authenticated
  USING (
    user_id IN (
      SELECT id 
      FROM public.user_profiles 
      WHERE id = (select auth.uid())
    )
  )
  WITH CHECK (
    user_id IN (
      SELECT id 
      FROM public.user_profiles 
      WHERE id = (select auth.uid())
    )
  );

-- =====================================================
-- 12. OPTIMIZE RLS POLICIES - PORTFOLIO_GOALS
-- =====================================================

DROP POLICY IF EXISTS "Users can view own portfolio goals" ON public.portfolio_goals;
DROP POLICY IF EXISTS "Users can insert own portfolio goals" ON public.portfolio_goals;
DROP POLICY IF EXISTS "Users can update own portfolio goals" ON public.portfolio_goals;

CREATE POLICY "Users can view own portfolio goals"
  ON public.portfolio_goals
  FOR SELECT
  TO authenticated
  USING (
    user_id IN (
      SELECT id 
      FROM public.user_profiles 
      WHERE id = (select auth.uid())
    )
  );

CREATE POLICY "Users can insert own portfolio goals"
  ON public.portfolio_goals
  FOR INSERT
  TO authenticated
  WITH CHECK (
    user_id IN (
      SELECT id 
      FROM public.user_profiles 
      WHERE id = (select auth.uid())
    )
  );

CREATE POLICY "Users can update own portfolio goals"
  ON public.portfolio_goals
  FOR UPDATE
  TO authenticated
  USING (
    user_id IN (
      SELECT id 
      FROM public.user_profiles 
      WHERE id = (select auth.uid())
    )
  )
  WITH CHECK (
    user_id IN (
      SELECT id 
      FROM public.user_profiles 
      WHERE id = (select auth.uid())
    )
  );

-- =====================================================
-- 13. OPTIMIZE RLS POLICIES - COMMUNITY_PREFERENCES
-- =====================================================

DROP POLICY IF EXISTS "Users can view own community preferences" ON public.community_preferences;
DROP POLICY IF EXISTS "Users can insert own community preferences" ON public.community_preferences;
DROP POLICY IF EXISTS "Users can update own community preferences" ON public.community_preferences;

CREATE POLICY "Users can view own community preferences"
  ON public.community_preferences
  FOR SELECT
  TO authenticated
  USING (
    user_id IN (
      SELECT id 
      FROM public.user_profiles 
      WHERE id = (select auth.uid())
    )
  );

CREATE POLICY "Users can insert own community preferences"
  ON public.community_preferences
  FOR INSERT
  TO authenticated
  WITH CHECK (
    user_id IN (
      SELECT id 
      FROM public.user_profiles 
      WHERE id = (select auth.uid())
    )
  );

CREATE POLICY "Users can update own community preferences"
  ON public.community_preferences
  FOR UPDATE
  TO authenticated
  USING (
    user_id IN (
      SELECT id 
      FROM public.user_profiles 
      WHERE id = (select auth.uid())
    )
  )
  WITH CHECK (
    user_id IN (
      SELECT id 
      FROM public.user_profiles 
      WHERE id = (select auth.uid())
    )
  );

-- =====================================================
-- 14. FIX FUNCTION SEARCH PATH
-- =====================================================

CREATE OR REPLACE FUNCTION public.update_updated_at_column()
RETURNS TRIGGER
SECURITY DEFINER
SET search_path = public
LANGUAGE plpgsql
AS $$
BEGIN
  NEW.updated_at = now();
  RETURN NEW;
END;
$$;